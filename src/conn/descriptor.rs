use std::{
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroU64,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use http::{Uri, Version};
use lru::DefaultHasher;

use crate::{
    conn::net::SocketBindOptions,
    group::{Group, ScopeRef},
    proxy::Matcher,
    tls::TlsOptions,
};

/// A key that uniquely identifies a group of interchangeable connections for pooling.
///
/// This ID is derived from all parameters that define a connection endpoint,
/// such as URI, proxy, and local socket bindings. Connections with the same
/// ID are considered equivalent and can be reused.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionId(Arc<(Group, AtomicU64)>);

/// A blueprint for creating a new client connection, containing all necessary parameters.
///
/// This descriptor bundles the target `Uri`, HTTP version, `TlsOptions`, proxy settings,
/// and other configurations needed to establish a connection.
#[must_use]
#[derive(Clone)]
pub(crate) struct ConnectionDescriptor {
    uri: Uri,
    version: Option<Version>,
    proxy: Option<Matcher>,
    tls_options: Option<TlsOptions>,
    socket_bind: Option<SocketBindOptions>,
    scope: Option<ScopeRef>,
    connection_id: ConnectionId,
    session_id: ConnectionId,
}

// ===== impl ConnectionId =====

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let hash = self.0.1.load(Ordering::Relaxed);
        if hash != 0 {
            state.write_u64(hash);
            return;
        }

        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let computed_hash = NonZeroU64::new(HASHER.hash_one(&self.0.0))
            .map(NonZeroU64::get)
            .unwrap_or(1);

        let _ = self.0.1.compare_exchange(
            u64::MIN,
            computed_hash,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        state.write_u64(computed_hash);
    }
}

impl PartialEq for ConnectionId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.0.eq(&other.0.0)
    }
}

impl Eq for ConnectionId {}

// ===== impl ConnectionDescriptor =====

impl ConnectionDescriptor {
    /// Create a new [`ConnectionDescriptor`].
    pub(crate) fn new(
        uri: Uri,
        mut group: Group,
        scope: Option<ScopeRef>,
        proxy: Option<Matcher>,
        version: Option<Version>,
        tls_options: Option<TlsOptions>,
        socket_bind: Option<SocketBindOptions>,
    ) -> ConnectionDescriptor {
        let id = |group| ConnectionId(Arc::new((group, AtomicU64::new(u64::MIN))));
        group
            .uri(uri.clone())
            .version(version)
            .proxy(proxy.clone())
            .socket_bind(socket_bind.clone());
        // TLS sessions resume across scopes; connections stay within theirs.
        let (connection_id, session_id) = match &scope {
            Some(scope) => {
                let session_id = id(group.clone());
                group.scope(scope.clone());
                (id(group), session_id)
            }
            None => {
                let connection_id = id(group);
                (connection_id.clone(), connection_id)
            }
        };

        ConnectionDescriptor {
            uri,
            proxy,
            version,
            tls_options,
            socket_bind,
            scope,
            connection_id,
            session_id,
        }
    }

    /// Returns a [`ConnectionId`] group ID for this descriptor.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// Returns the ID the connection's TLS sessions are cached under.
    #[inline]
    pub(crate) fn session_id(&self) -> ConnectionId {
        self.session_id.clone()
    }

    /// Returns the scope the connection is confined to, if any.
    #[inline]
    pub(crate) fn scope(&self) -> Option<&ScopeRef> {
        self.scope.as_ref()
    }

    /// Returns the TLS server name to announce instead of the URI host, if set
    /// (`Some(None)`: no name).
    #[inline]
    pub(crate) fn tls_server_name(&self) -> Option<Option<&str>> {
        self.connection_id.0.0.tls_server_name()
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Return the negotiated HTTP version, if any.
    pub(crate) fn version(&self) -> Option<Version> {
        self.version
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Return a reference to the [`Matcher`].
    #[inline]
    pub(crate) fn proxy(&self) -> Option<&Matcher> {
        self.proxy.as_ref()
    }

    /// Return a reference to the [`SocketBindOptions`].
    #[inline]
    pub(crate) fn socket_bind_options(&self) -> Option<&SocketBindOptions> {
        self.socket_bind.as_ref()
    }
}
