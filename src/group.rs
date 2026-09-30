//! # Request Grouping Mechanism
//!
//! This module provides the [`Group`] structure, which defines the logical boundaries
//! for categorizing and segregating outbound requests.
//!
//! ## Concept
//! A `Group` acts as a multi-dimensional identity for a request. In complex networking
//! stack environments, two requests targeting the same destination may belong to
//! distinct logical groups due to different metadata, security contexts, or
//! routing requirements.
//!
//! ## Logical Segregation
//! By assigning requests to different groups, the system ensures:
//! 1. **Contextual Isolation**: Requests are processed and dispatched within their defined logical
//!    partitions.
//! 2. **Deterministic Identity**: The internal `BTreeMap` ensures that the identity of a group is
//!    stable and invariant to the order in which grouping criteria are applied.
//! 3. **Resource Affinity**: Resource management (such as connection pooling) respects these
//!    boundaries, ensuring that resources are never leaked across different request groups.

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};

use http::{Uri, Version};
use name::GroupId;
use tokio::sync::watch;
use wreq_proto::http2::Control;

use crate::{conn::net::SocketBindOptions, proxy::Matcher, sync::Mutex};

macro_rules! impl_group_variants {
    ($($name:ident $(($ty:ty))?,)*) => {
        #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
        enum GroupKey {
            $($name,)*
        }

        #[derive(Debug, Clone, Hash, PartialEq, Eq)]
        enum GroupVariant {
            $($name $(($ty))?,)*
        }
    }
}

impl_group_variants! {
    Request(Group),
    Emulate(Group),
    Named(GroupId),
    Uri(Uri),
    Version(Version),
    Proxy(Matcher),
    SocketBind(Option<SocketBindOptions>),
    ServerName(Option<Box<str>>),
    VerifyName(Box<str>),
    AcceptedCertificate([u8; 32]),
    Scope(ScopeRef),
}

/// A logical identifier for request grouping.
///
/// `Group` encapsulates the criteria that define a request's execution context.
/// Requests with non-identical `Group` states are treated as belonging to
/// different logical partitions, preventing unintended interaction or
/// resource sharing between them.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Group(BTreeMap<GroupKey, GroupVariant>);

impl Group {
    /// Creates a new [`Group`] with a custom string or numeric identifier.
    #[inline]
    pub fn new<N: Into<GroupId>>(name: N) -> Self {
        Group(BTreeMap::from([(
            GroupKey::Named,
            GroupVariant::Named(name.into()),
        )]))
    }

    /// Groups the request by a specific target [`Uri`].
    #[inline]
    pub(crate) fn uri(&mut self, uri: Uri) -> &mut Self {
        self.extend(GroupKey::Uri, GroupVariant::Uri(uri))
    }

    /// Groups the request by its required HTTP [`Version`].
    #[inline]
    pub(crate) fn version(&mut self, version: Option<Version>) -> &mut Self {
        self.extend(GroupKey::Version, version.map(GroupVariant::Version))
    }

    /// Groups the request based on its proxy [`Matcher`] criteria.
    #[inline]
    pub(crate) fn proxy(&mut self, proxy: Option<Matcher>) -> &mut Self {
        self.extend(GroupKey::Proxy, proxy.map(GroupVariant::Proxy))
    }

    /// Groups the request by its resolved socket bind options.
    #[inline]
    pub(crate) fn socket_bind(&mut self, opts: Option<SocketBindOptions>) -> &mut Self {
        self.extend(GroupKey::SocketBind, GroupVariant::SocketBind(opts))
    }

    /// Groups the request by the TLS server name it announces instead of its URI host
    /// (`None`: no name).
    #[inline]
    pub(crate) fn server_name(&mut self, name: Option<Box<str>>) -> &mut Self {
        self.extend(GroupKey::ServerName, GroupVariant::ServerName(name))
    }

    /// Groups the request by the name TLS verifies instead of its URI host while announcing
    /// none.
    #[inline]
    pub(crate) fn verify_name(&mut self, name: Option<Box<str>>) -> &mut Self {
        self.extend(GroupKey::VerifyName, name.map(GroupVariant::VerifyName))
    }

    /// Groups the request by the SHA-256 of the leaf certificate its TLS accepts even when
    /// verification fails.
    #[inline]
    pub(crate) fn accepted_certificate(&mut self, leaf_sha256: Option<[u8; 32]>) -> &mut Self {
        self.extend(
            GroupKey::AcceptedCertificate,
            leaf_sha256.map(GroupVariant::AcceptedCertificate),
        )
    }

    /// Confines the request's connections to a [`ConnectionScope`].
    #[inline]
    pub(crate) fn scope(&mut self, scope: ScopeRef) -> &mut Self {
        self.extend(GroupKey::Scope, GroupVariant::Scope(scope))
    }

    /// Creates a nested request group.
    #[inline]
    pub(crate) fn request(&mut self, group: Group) -> &mut Self {
        self.extend(GroupKey::Request, GroupVariant::Request(group))
    }

    /// Groups the request by its emulation-layer characteristics.
    #[inline]
    pub(crate) fn emulate(&mut self, group: Group) -> &mut Self {
        self.extend(GroupKey::Emulate, GroupVariant::Emulate(group))
    }

    #[inline]
    fn extend<T: Into<Option<GroupVariant>>>(&mut self, id: GroupKey, entry: T) -> &mut Self {
        if let Some(entry) = entry.into() {
            self.0.insert(id, entry);
        }
        self
    }
}

impl From<u64> for Group {
    #[inline]
    fn from(value: u64) -> Self {
        Group::new(value)
    }
}

impl From<&'static str> for Group {
    #[inline]
    fn from(value: &'static str) -> Self {
        Group::new(value)
    }
}

impl From<String> for Group {
    #[inline]
    fn from(value: String) -> Self {
        Group::new(value)
    }
}

impl From<Box<str>> for Group {
    #[inline]
    fn from(value: Box<str>) -> Self {
        Group::new(value)
    }
}

/// Confines the connections requests open to one lifetime: a connection serves only
/// requests of the scope it was opened for, and closes, idle or not, once every clone of
/// the scope is dropped.
#[derive(Clone)]
pub struct ConnectionScope(Arc<(u64, watch::Sender<()>, Arc<Connections>)>);

/// The HTTP/2 connections open in a scope, each by an id, able to send frames of the
/// caller's choosing, the first connection opened in it, once one is: the [`Control`] of
/// an HTTP/2 one, `None` for an HTTP/1 one, how they end (a [`ConnectionEnd`]), and what
/// the caller sent them before the first opened, which that one sends should it speak
/// HTTP/2.
#[derive(Default)]
struct Connections {
    http2: Mutex<Vec<(u64, Control)>>,
    first: watch::Sender<Option<Option<Control>>>,
    end: AtomicU8,
    pending: Mutex<Vec<Box<dyn Fn(&Control) + Send>>>,
}

/// Called each time the request carrying it (as an extension) is queued on the connection
/// sending it, which sends the requests queued on it in that order.
#[derive(Clone)]
pub struct OnQueued(Arc<dyn Fn() + Send + Sync>);

impl OnQueued {
    /// Calls `queued` each time the request is queued on its connection.
    pub fn new(queued: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(queued))
    }

    pub(crate) fn queued(&self) {
        (self.0)();
    }
}

/// How a [`ConnectionScope`]'s connections end (see [`ConnectionScope::end_with`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionEnd {
    /// As a client done with them ends them, once they close: an HTTP/2 connection's
    /// GOAWAY, then TLS's close_notify, then a FIN.
    #[default]
    Graceful = 0,
    /// With a FIN alone, sending nothing more: no GOAWAY, no close_notify.
    Fin = 1,
    /// With a TCP reset, sending nothing more.
    Reset = 2,
}

impl Connections {
    fn opened(&self, control: Option<Control>) {
        self.first.send_if_modified(|first| {
            let none = first.is_none();
            if none {
                *first = Some(control);
            }
            none
        });
    }
}

impl ConnectionScope {
    /// Creates a scope no other scope's requests share connections with.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let (closed, _) = watch::channel(());
        ConnectionScope(Arc::new((
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
            closed,
            Arc::default(),
        )))
    }

    pub(crate) fn handle(&self) -> ScopeRef {
        ScopeRef {
            id: self.0.0,
            closed: self.0.1.subscribe(),
            connections: self.0.2.clone(),
        }
    }

    /// The [`Control`] of the first connection opened in this scope, once one is; `None`
    /// when that connection speaks HTTP/1 (no later HTTP/2 one is told).
    pub async fn first_http2(&self) -> Option<Control> {
        let mut first = self.0.2.first.subscribe();
        first
            .wait_for(Option::is_some)
            .await
            .expect("the scope holds the sender")
            .clone()
            .flatten()
    }

    /// Sends a SETTINGS frame of exactly `params`, `(identifier, value)` in order, on each
    /// HTTP/2 connection open in this scope, following the request recorded as `after` (see
    /// [`Control::after_request`]), once the previous one it sent was acknowledged; the
    /// known parameters apply to it on the acknowledgement. Before the scope's first
    /// connection opened, that one sends it, should it speak HTTP/2, as the frames below.
    pub fn send_http2_settings(&self, after: u32, params: &[(u16, u32)]) {
        let params = params.to_vec();
        self.on_http2(move |control| {
            control
                .after_request(after)
                .send_settings(params.iter().copied())
        });
    }

    /// Sends a PING carrying `payload` on each HTTP/2 connection open in this scope,
    /// following the request recorded as `after` (see [`Control::after_request`]).
    pub fn send_http2_ping(&self, after: u32, payload: [u8; 8]) {
        self.on_http2(move |control| control.after_request(after).send_ping(payload));
    }

    /// Sends `priority`, a PRIORITY frame numbered as the connection requests were recorded
    /// on numbered streams, on each HTTP/2 connection open in this scope, as it numbers them
    /// (see [`Control::send_priority`]), following the request recorded as `after` (see
    /// [`Control::after_request`]).
    pub fn send_http2_priority(&self, after: u32, priority: &http2::frame::Priority) {
        let priority = priority.clone();
        self.on_http2(move |control| control.after_request(after).send_priority(priority.clone()));
    }

    /// Sends a PRIORITY_UPDATE frame (RFC 9218) giving `stream_id`, numbered as the
    /// connection requests were recorded on numbered it, the priority `field_value` on each
    /// HTTP/2 connection open in this scope, as it numbers it (see
    /// [`Control::send_priority_update`]), following the request recorded as `after` (see
    /// [`Control::after_request`]).
    pub fn send_http2_priority_update(&self, after: u32, stream_id: u32, field_value: &[u8]) {
        let field_value = field_value.to_vec();
        self.on_http2(move |control| {
            control
                .after_request(after)
                .send_priority_update(stream_id, &field_value)
        });
    }

    /// Sends a WINDOW_UPDATE of `increment` for the connection (`stream_id` 0) or the
    /// request recorded as `stream_id` on each HTTP/2 connection open in this scope, as it
    /// numbers it (see [`Control::send_window_update`]), following the request recorded as
    /// `after` (see [`Control::after_request`]).
    pub fn send_http2_window_update(&self, after: u32, stream_id: u32, increment: u32) {
        self.on_http2(move |control| {
            control
                .after_request(after)
                .send_window_update(stream_id, increment)
        });
    }

    /// Tells each HTTP/2 connection open in this scope that the request recorded as
    /// `recorded` won't be sent on it unless it was (see [`Control::release_request`]).
    pub fn release_http2_request(&self, recorded: u32) {
        self.on_http2(move |control| control.release_request(recorded));
    }

    /// Runs `send` on each HTTP/2 connection open in this scope, or, before the scope's
    /// first connection opened, on that one should it speak HTTP/2.
    fn on_http2(&self, send: impl Fn(&Control) + Send + 'static) {
        let http2 = self.0.2.http2.lock();
        if self.0.2.first.borrow().is_none() {
            self.0.2.pending.lock().push(Box::new(send));
            return;
        }
        for (_, control) in http2.iter() {
            send(control);
        }
    }

    /// Makes the receive window of the request recorded as `recorded`, on the HTTP/2
    /// connection of this scope it was sent on, grow only by the WINDOW_UPDATEs
    /// [`Self::send_http2_window_update`] sends (see [`Control::mirror_stream_window`]).
    pub fn mirror_http2_stream_window(&self, recorded: u32) {
        self.on_http2(move |control| control.mirror_stream_window(recorded));
    }

    /// Makes this scope's connections end as `end` says rather than gracefully: past
    /// [`ConnectionEnd::Fin`] or [`ConnectionEnd::Reset`] they send nothing more, and end
    /// so once they close, as they do once the scope is dropped.
    pub fn end_with(&self, end: ConnectionEnd) {
        self.0.2.end.store(end as u8, Ordering::Release);
    }
}

impl Default for ConnectionScope {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConnectionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConnectionScope").field(&self.0.0).finish()
    }
}

/// A [`ConnectionScope`]'s identity and end, held by its requests and connections without
/// keeping it alive.
#[derive(Clone)]
pub(crate) struct ScopeRef {
    id: u64,
    closed: watch::Receiver<()>,
    connections: Arc<Connections>,
}

/// An HTTP/2 connection's place among its scope's, which it leaves when dropped.
pub(crate) struct Http2Registration {
    id: u64,
    connections: Arc<Connections>,
}

impl Drop for Http2Registration {
    fn drop(&mut self) {
        self.connections
            .http2
            .lock()
            .retain(|(id, _)| *id != self.id);
    }
}

impl ScopeRef {
    /// Makes the scope's HTTP/2 frames go on the connection `control` sends on, until the
    /// registration returned is dropped, and tells it as the scope's first connection
    /// should it be.
    pub(crate) fn register_http2(&self, control: Control) -> Http2Registration {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut http2 = self.connections.http2.lock();
        for send in self.connections.pending.lock().drain(..) {
            send(&control);
        }
        http2.push((id, control.clone()));
        self.connections.opened(Some(control));
        drop(http2);
        Http2Registration {
            id,
            connections: self.connections.clone(),
        }
    }

    /// Tells an HTTP/1 connection opened as the scope's first connection, should it be,
    /// dropping what the caller sent its HTTP/2 connections before.
    pub(crate) fn opened_http1(&self) {
        let _http2 = self.connections.http2.lock();
        self.connections.pending.lock().clear();
        self.connections.opened(None);
    }

    /// How the scope's connections end (see [`ConnectionScope::end_with`]).
    pub(crate) fn end(&self) -> ConnectionEnd {
        match self.connections.end.load(Ordering::Acquire) {
            1 => ConnectionEnd::Fin,
            2 => ConnectionEnd::Reset,
            _ => ConnectionEnd::Graceful,
        }
    }

    /// Resolves once the scope is dropped.
    pub(crate) async fn closed(mut self) {
        // Nothing is ever sent, so this returns only when the sender is gone.
        let _ = self.closed.changed().await;
    }
}

impl Hash for ScopeRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for ScopeRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ScopeRef {}

impl std::fmt::Debug for ScopeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ScopeRef").field(&self.id).finish()
    }
}

mod name {

    /// A group identifier that can be a string or a numeric tag.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum GroupId {
        Borrowed(&'static str),
        Owned(Box<str>),
        Number(u64),
    }

    impl From<&'static str> for GroupId {
        #[inline]
        fn from(value: &'static str) -> Self {
            Self::Borrowed(value)
        }
    }

    impl From<String> for GroupId {
        #[inline]
        fn from(value: String) -> Self {
            Self::Owned(value.into_boxed_str())
        }
    }

    impl From<Box<str>> for GroupId {
        #[inline]
        fn from(value: Box<str>) -> Self {
            Self::Owned(value)
        }
    }

    impl From<u64> for GroupId {
        #[inline]
        fn from(value: u64) -> Self {
            Self::Number(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn test_group_identity_invariance() {
        let mut g1 = Group::default();
        g1.extend(GroupKey::Named, GroupVariant::Named("worker".into()));
        g1.extend(GroupKey::Version, GroupVariant::Version(Version::HTTP_2));

        let mut g2 = Group::default();
        g2.extend(GroupKey::Version, GroupVariant::Version(Version::HTTP_2));
        g2.extend(GroupKey::Named, GroupVariant::Named("worker".into()));

        let mut h1 = DefaultHasher::new();
        g1.hash(&mut h1);

        let mut h2 = DefaultHasher::new();
        g2.hash(&mut h2);

        assert_eq!(
            h1.finish(),
            h2.finish(),
            "Request groups must maintain identical hashes regardless of criteria insertion order"
        );
    }
}
