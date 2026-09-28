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
        atomic::{AtomicU64, Ordering},
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
pub struct ConnectionScope(Arc<(u64, watch::Sender<()>, Http2Controls)>);

/// The HTTP/2 connections open in a scope, each by an id, able to send frames of the
/// caller's choosing.
type Http2Controls = Arc<Mutex<Vec<(u64, Control)>>>;

impl ConnectionScope {
    /// Creates a scope no other scope's requests share connections with.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let (closed, _) = watch::channel(());
        ConnectionScope(Arc::new((
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
            closed,
            Http2Controls::default(),
        )))
    }

    pub(crate) fn handle(&self) -> ScopeRef {
        ScopeRef {
            id: self.0.0,
            closed: self.0.1.subscribe(),
            http2: self.0.2.clone(),
        }
    }

    /// Sends a SETTINGS frame of exactly `params`, `(identifier, value)` in order, on each
    /// HTTP/2 connection open in this scope, once the previous one it sent was
    /// acknowledged; the known parameters apply to it on the acknowledgement.
    pub fn send_http2_settings(&self, params: &[(u16, u32)]) {
        for (_, control) in self.0.2.lock().iter() {
            control.send_settings(params.iter().copied());
        }
    }

    /// Sends a PING carrying `payload` on each HTTP/2 connection open in this scope.
    pub fn send_http2_ping(&self, payload: [u8; 8]) {
        for (_, control) in self.0.2.lock().iter() {
            control.send_ping(payload);
        }
    }

    /// Sets when each HTTP/2 connection open in this scope sends a WINDOW_UPDATE: once
    /// `connection`, for the connection, or `stream`, for the streams it opens from now on,
    /// bytes of received data were released since the last, rather than once half the
    /// window was (`None`).
    pub fn set_http2_window_update_thresholds(&self, connection: Option<u32>, stream: Option<u32>) {
        for (_, control) in self.0.2.lock().iter() {
            control.set_window_update_thresholds(connection, stream);
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
    http2: Http2Controls,
}

/// An HTTP/2 connection's place among its scope's, which it leaves when dropped.
pub(crate) struct Http2Registration {
    id: u64,
    controls: Http2Controls,
}

impl Drop for Http2Registration {
    fn drop(&mut self) {
        self.controls.lock().retain(|(id, _)| *id != self.id);
    }
}

impl ScopeRef {
    /// Makes the scope's HTTP/2 frames go on the connection `control` sends on, until the
    /// registration returned is dropped.
    pub(crate) fn register_http2(&self, control: Control) -> Http2Registration {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.http2.lock().push((id, control));
        Http2Registration {
            id,
            controls: self.http2.clone(),
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
