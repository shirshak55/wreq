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

#[cfg(feature = "tokio-rt")]
use crate::tls::conn::Preconnected;
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
    tls_name: Option<(Box<str>, bool)>,
    accepted_certificate: Option<[u8; 32]>,
    #[cfg(feature = "tokio-rt")]
    preconnected: Option<Preconnected>,
    connection_id: ConnectionId,
    session_id: ConnectionId,
    unversioned_id: Option<ConnectionId>,
}

// ===== impl ConnectionId =====

impl ConnectionId {
    /// The ID of the connections `group` describes.
    pub(crate) fn new(group: Group) -> Self {
        ConnectionId(Arc::new((group, AtomicU64::new(u64::MIN))))
    }
}

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
            .proxy(proxy.clone())
            .socket_bind(socket_bind.clone());
        // An idle HTTP/1 connection opened without a forced version serves a request that
        // forces HTTP/1 just as well.
        let mut unversioned =
            matches!(version, Some(Version::HTTP_10 | Version::HTTP_11)).then(|| group.clone());
        group.version(version);
        // TLS sessions resume across scopes; connections stay within theirs.
        let (connection_id, session_id) = match &scope {
            Some(scope) => {
                let session_id = id(group.clone());
                group.scope(scope.clone());
                if let Some(unversioned) = &mut unversioned {
                    unversioned.scope(scope.clone());
                }
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
            tls_name: None,
            accepted_certificate: None,
            #[cfg(feature = "tokio-rt")]
            preconnected: None,
            connection_id,
            session_id,
            unversioned_id: unversioned.map(id),
        }
    }

    /// Sets the name the TLS handshake verifies instead of the URI host, and whether it
    /// announces it (SNI).
    pub(crate) fn with_tls_name(mut self, tls_name: Option<(Box<str>, bool)>) -> Self {
        self.tls_name = tls_name;
        self
    }

    /// Sets the SHA-256 of the leaf certificate (its DER) the TLS handshake accepts even
    /// when verification fails.
    pub(crate) fn with_accepted_certificate(mut self, leaf_sha256: Option<[u8; 32]>) -> Self {
        self.accepted_certificate = leaf_sha256;
        self
    }

    /// Offers a connection for the connection attempt to adopt instead of opening one.
    #[cfg(feature = "tokio-rt")]
    pub(crate) fn with_preconnected(mut self, preconnected: Option<Preconnected>) -> Self {
        self.preconnected = preconnected;
        self
    }

    /// The connection offered for adoption, if any.
    #[cfg(feature = "tokio-rt")]
    #[inline]
    pub(crate) fn preconnected(&self) -> Option<&Preconnected> {
        self.preconnected.as_ref()
    }

    /// Returns a [`ConnectionId`] group ID for this descriptor.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// For a request that forces HTTP/1, the ID its connections would have without the
    /// forced version: idle HTTP/1 connections there can serve it too.
    #[inline]
    pub(crate) fn unversioned_id(&self) -> Option<&ConnectionId> {
        self.unversioned_id.as_ref()
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

    /// Returns the name the TLS handshake verifies instead of the URI host, and whether it
    /// announces it, if set.
    #[inline]
    pub(crate) fn tls_name(&self) -> Option<(&str, bool)> {
        self.tls_name.as_ref().map(|(name, sni)| (&**name, *sni))
    }

    /// Returns the SHA-256 of the leaf certificate the TLS handshake accepts even when
    /// verification fails, if set.
    #[inline]
    pub(crate) fn accepted_certificate(&self) -> Option<[u8; 32]> {
        self.accepted_certificate
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Opens the connection to `uri` itself (a proxy), whose TLS then names its host and
    /// accepts no certificate failing verification.
    #[inline]
    pub(crate) fn set_uri(&mut self, uri: Uri) {
        self.uri = uri;
        self.tls_name = None;
        self.accepted_certificate = None;
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
