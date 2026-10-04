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
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::Waker,
};

use bytes::Bytes;
use http::{Uri, Version};
use name::GroupId;
use tokio::sync::{Notify, mpsc, watch};
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
    MinDheBits(u16),
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

    /// Groups the request by the smallest DHE group its TLS accepts.
    #[inline]
    pub(crate) fn min_dhe_bits(&mut self, bits: u16) -> &mut Self {
        self.extend(GroupKey::MinDheBits, GroupVariant::MinDheBits(bits))
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
/// an HTTP/2 one, `None` for an HTTP/1 one, how they end (a [`ConnectionEnd`], 0 until
/// told, else one past it) and the tasks waiting to be told, what the caller sent them
/// before the first opened, which that one sends should it speak HTTP/2, how their
/// origins end the HTTP/2 ones, and how many HTTP/1 ones are open, told once an origin
/// closed the last.
#[derive(Default)]
struct Connections {
    http2: Mutex<Vec<(u64, Control)>>,
    first: watch::Sender<Option<Option<Control>>>,
    end: AtomicU8,
    end_tasks: Mutex<Vec<Waker>>,
    pending: Mutex<Vec<Box<dyn Fn(&Control) + Send>>>,
    origin_ends: OriginEnds,
    http1_open: AtomicUsize,
    http1_origin_closed: Notify,
}

/// How the origins of a scope's HTTP/2 connections end them, as they do, until the caller
/// takes them (see [`ConnectionScope::http2_origin_ends`]).
struct OriginEnds {
    sender: mpsc::UnboundedSender<Http2OriginEnd>,
    receiver: Mutex<Option<mpsc::UnboundedReceiver<Http2OriginEnd>>>,
}

impl Default for OriginEnds {
    fn default() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        OriginEnds {
            sender,
            receiver: Mutex::new(Some(receiver)),
        }
    }
}

impl OriginEnds {
    fn tell(&self, end: Http2OriginEnd) {
        // Refused once the caller no longer listens.
        let _ = self.sender.send(end);
    }
}

/// How the origin of one of a scope's HTTP/2 connections ends it, in the order it does (see
/// [`ConnectionScope::http2_origin_ends`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Http2OriginEnd {
    /// It sent a GOAWAY: its last stream, numbered as the scope's requests were recorded on
    /// numbered it (see [`Control::on_go_away`]), its error code and its debug data.
    GoAway {
        /// The last stream it processed.
        last_stream_id: u32,
        /// The error code.
        error_code: u32,
        /// The debug data.
        debug_data: Bytes,
    },
    /// It closed the connection: with TLS's close_notify or not, by a TCP reset or not.
    Closed {
        /// Whether it sent its close_notify.
        close_notify: bool,
        /// Whether it reset the connection.
        reset: bool,
    },
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

/// How a [`ConnectionScope`]'s connections end (see [`ConnectionScope::end_with`]). An
/// HTTP/2 one sends no GOAWAY of its own: only those
/// [`ConnectionScope::send_http2_go_away`] sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionEnd {
    /// With TLS's close_notify, then a FIN, once they close.
    #[default]
    Graceful = 0,
    /// With a FIN alone, sending nothing more: no close_notify.
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

    /// Sends a frame of a type HTTP/2 doesn't define, of `kind`, `flags` and `payload`, on
    /// the connection (`stream_id` 0) or the request recorded as `stream_id` on each HTTP/2
    /// connection open in this scope, as it numbers it (see [`Control::send_unknown`]),
    /// following the request recorded as `after` (see [`Control::after_request`]).
    pub fn send_http2_unknown(
        &self,
        after: u32,
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) {
        let payload = payload.to_vec();
        self.on_http2(move |control| {
            control
                .after_request(after)
                .send_unknown(kind, flags, stream_id, &payload)
        });
    }

    /// Makes the request recorded as `recorded`, on the HTTP/2 connection of this scope it
    /// was sent on, reset with `error_code` rather than its own should it be dropped before
    /// it ends or reset (see [`Control::cancel_with`]): as its client reset it.
    pub fn send_http2_reset(&self, recorded: u32, error_code: u32) {
        self.on_http2(move |control| control.cancel_with(recorded, error_code.into()));
    }

    /// Tells each HTTP/2 connection open in this scope that the request recorded as
    /// `recorded` won't be sent on it unless it was (see [`Control::release_request`]).
    pub fn release_http2_request(&self, recorded: u32) {
        self.on_http2(move |control| control.release_request(recorded));
    }

    /// Sends a GOAWAY frame of `error_code` and `debug_data` naming `last_stream_id`, a
    /// request's numbered as the connection numbers it (see [`Control::send_go_away`]), on
    /// each HTTP/2 connection open in this scope, following the request recorded as `after`
    /// (see [`Control::after_request`]); they then close without a GOAWAY of their own.
    pub fn send_http2_go_away(
        &self,
        after: u32,
        last_stream_id: u32,
        error_code: u32,
        debug_data: &[u8],
    ) {
        let debug_data = debug_data.to_vec();
        self.on_http2(move |control| {
            control.after_request(after).send_go_away(
                last_stream_id,
                error_code.into(),
                &debug_data,
            )
        });
    }

    /// Resolves once the origin of an HTTP/1 connection open in this scope closed it, with no
    /// other open: as a client's own connection to it would have closed.
    pub async fn http1_origin_closed(&self) {
        self.0.2.http1_origin_closed.notified().await;
    }

    /// How the origins of this scope's HTTP/2 connections end them, as they do: each GOAWAY
    /// they send, then how they close. Taken by the first call, `None` after it.
    pub fn http2_origin_ends(&self) -> Option<mpsc::UnboundedReceiver<Http2OriginEnd>> {
        self.0.2.origin_ends.receiver.lock().take()
    }

    /// Resolves once each HTTP/2 connection open in this scope sent the frames this scope had
    /// it send, or ended (see [`Control::sent`]).
    pub async fn http2_sent(&self) {
        let http2 = self.0.2.http2.lock().clone();
        for (_, control) in http2 {
            control.sent().await;
        }
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

    /// Makes this scope's connections end as `end` says: past [`ConnectionEnd::Fin`] or
    /// [`ConnectionEnd::Reset`] they send nothing more, and end so once they close, as they
    /// do once the scope is dropped. An HTTP/2 connection whose origin closed it first
    /// waits a moment for it before closing, else ends with a FIN alone; one closing
    /// otherwise before it ends gracefully.
    pub fn end_with(&self, end: ConnectionEnd) {
        self.0.2.end.store(end as u8 + 1, Ordering::Release);
        for task in self.0.2.end_tasks.lock().drain(..) {
            task.wake();
        }
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

/// An HTTP/1 connection counted open in its scope until dropped, closed by its origin when
/// `by_origin`.
pub(crate) struct Http1Open {
    connections: Arc<Connections>,
    pub(crate) by_origin: bool,
}

impl Drop for Http1Open {
    fn drop(&mut self) {
        if self.connections.http1_open.fetch_sub(1, Ordering::AcqRel) == 1 && self.by_origin {
            self.connections.http1_origin_closed.notify_one();
        }
    }
}

impl ScopeRef {
    /// Makes the scope's HTTP/2 frames go on the connection `control` sends on, until the
    /// registration returned is dropped, and tells it as the scope's first connection
    /// should it be.
    pub(crate) fn register_http2(&self, control: Control) -> Http2Registration {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        control.leave_close_to_caller();
        let connections = Arc::downgrade(&self.connections);
        control.on_go_away(move |last_stream_id, reason, debug_data| {
            if let Some(connections) = connections.upgrade() {
                connections.origin_ends.tell(Http2OriginEnd::GoAway {
                    last_stream_id,
                    error_code: reason.into(),
                    debug_data,
                });
            }
        });
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
        self.ended().unwrap_or_default()
    }

    /// How the scope's connections end, once told (see [`ConnectionScope::end_with`]).
    pub(crate) fn ended(&self) -> Option<ConnectionEnd> {
        match self.connections.end.load(Ordering::Acquire) {
            0 => None,
            2 => Some(ConnectionEnd::Fin),
            3 => Some(ConnectionEnd::Reset),
            _ => Some(ConnectionEnd::Graceful),
        }
    }

    /// Wakes `task` once the scope is told how its connections end, unless it was already.
    pub(crate) fn wake_on_end(&self, task: &Waker) -> Option<ConnectionEnd> {
        let mut tasks = self.connections.end_tasks.lock();
        let ended = self.ended();
        if ended.is_none() && !tasks.iter().any(|waiting| waiting.will_wake(task)) {
            tasks.push(task.clone());
        }
        ended
    }

    /// Counts an HTTP/1 connection open in the scope, from its connect on, until the
    /// [`Http1Open`] returned is dropped.
    pub(crate) fn http1_opened(&self) -> Http1Open {
        self.connections.http1_open.fetch_add(1, Ordering::AcqRel);
        Http1Open {
            connections: self.connections.clone(),
            by_origin: false,
        }
    }

    /// Tells the scope how the origin of one of its HTTP/2 connections closed it.
    pub(crate) fn origin_closed(&self, close_notify: bool, reset: bool) {
        self.connections.origin_ends.tell(Http2OriginEnd::Closed {
            close_notify,
            reset,
        });
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
