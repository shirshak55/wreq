//! SSL support via BoringSSL.

#[macro_use]
mod macros;
mod ext;
mod service;

use std::{
    borrow::Cow,
    fmt::{self, Debug},
    io,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    hash::MessageDigest,
    ssl::{
        ConnectConfiguration, HandshakeError, Ssl, SslConnector, SslMethod, SslOptions, SslRef,
        SslSessionCacheMode,
    },
};
use bytes::Bytes;
use ext::SslConnectorBuilderExt;
use http::{Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

use crate::{
    Error,
    conn::{Connected, Connection, TlsInfoFactory, descriptor::ConnectionDescriptor},
    tls::{
        AlpnProtocol, AlpsProtocol, KeyShare, TlsInfo, TlsOptions, TlsVersion,
        keylog::KeyLog,
        session::{Key, LruTlsSessionCache, TlsSession, TlsSessionCache},
        trust::{AiaCache, AiaFetch, CertStore, Identity, aia},
    },
};

fn key_index() -> Result<Index<Ssl, Key>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Key>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Where each connection keeps the first ClientHello it sent (see [`record_handshake_message`]).
pub(crate) fn client_hello_index() -> Result<Index<Ssl, bytes::Bytes>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, bytes::Bytes>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Where each connection keeps the origin's server-flight handshake messages, in the
/// order received (see [`record_handshake_message`] and [`crate::tls::ServerFlight`]),
/// shared with every [`crate::tls::TlsInfo`] taken of it, which reads it live: the
/// NewSessionTickets arrive after the handshake, once the connection is in use.
pub(crate) fn server_flight_index() -> Result<Index<Ssl, SharedFlight>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, SharedFlight>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// BoringSSL message callback keeping the exact ClientHello a connection sends and the
/// raw handshake messages the origin sends back (its server flight), so a connection's
/// `TlsInfo` carries both: the ClientHello for fingerprint measurement, and the server
/// flight (ServerHello, HelloRetryRequest, EncryptedExtensions, Certificate,
/// CertificateVerify, NewSessionTicket, and for TLS 1.2 ServerKeyExchange /
/// CertificateRequest) for a downstream server that reproduces it to the real client.
#[allow(unsafe_code)]
unsafe extern "C" fn record_handshake_message(
    is_write: std::os::raw::c_int,
    _version: std::os::raw::c_int,
    content_type: std::os::raw::c_int,
    buf: *const std::os::raw::c_void,
    len: usize,
    ssl: *mut btls_sys::SSL,
    _arg: *mut std::os::raw::c_void,
) {
    const HANDSHAKE: std::os::raw::c_int = 22;
    const CLIENT_HELLO: u8 = 1;
    if content_type != HANDSHAKE || buf.is_null() || len == 0 || ssl.is_null() {
        return;
    }
    // SAFETY: BoringSSL passes a live `SSL` and a message buffer of `len` bytes that stay
    // valid for the duration of the callback.
    let (message, ssl) = unsafe {
        (
            std::slice::from_raw_parts(buf.cast::<u8>(), len),
            <btls::ssl::SslRef as foreign_types::ForeignTypeRef>::from_ptr_mut(ssl),
        )
    };
    if is_write != 0 {
        // Our own ClientHello, kept once for fingerprint measurement.
        if message[0] != CLIENT_HELLO {
            return;
        }
        let Ok(index) = client_hello_index() else {
            return;
        };
        if ssl.ex_data(index).is_none() {
            ssl.set_ex_data(index, bytes::Bytes::copy_from_slice(message));
        }
        return;
    }
    // The origin's server flight, kept in order. NewSessionTickets arrive after the
    // handshake completes, so this keeps appending for the connection's whole life.
    let Ok(index) = server_flight_index() else {
        return;
    };
    let record = bytes::Bytes::copy_from_slice(message);
    if let Some(flight) = ssl.ex_data(index) {
        flight.lock().push(record);
    } else {
        ssl.set_ex_data(index, Arc::new(crate::sync::Mutex::new(vec![record])));
    }
}

/// A connection's server flight so far, shared with the `TlsInfo`s taken of it.
pub(crate) type SharedFlight = Arc<crate::sync::Mutex<Vec<bytes::Bytes>>>;

/// Settings for [`TlsConnector`]
#[derive(Clone)]
pub struct HandshakeSettings {
    no_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,
    alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,
    alps_use_new_codepoint: bool,
    key_shares: Option<Cow<'static, [KeyShare]>>,
    random_aes_hw_override: bool,
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls: TlsConnector,
}

/// A builder for creating a `TlsConnector`.
pub struct TlsConnectorBuilder {
    alpn_protocol: Option<AlpnProtocol>,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
    aia: Option<AiaCache>,
    keylog: Option<KeyLog>,
    session_cache: Arc<dyn TlsSessionCache>,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
    ssl: SslConnector,
    cache: Option<Arc<dyn TlsSessionCache>>,
    settings: HandshakeSettings,
}

// ===== impl HttpsConnector =====

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new [`HttpsConnector`] with a given [`TlsConnector`].
    #[inline]
    pub fn new(http: S, tls: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector { http, tls }
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.tls.settings.alpn_protocols = None;
        self
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Creates a new [`TlsConnectorBuilder`] with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            alpn_protocol: None,
            min_version: None,
            max_version: None,
            identity: None,
            tls_sni: true,
            verify_hostname: true,
            cert_store: None,
            cert_verification: true,
            aia: None,
            keylog: None,
            session_cache: Arc::new(LruTlsSessionCache::new(8)),
        }
    }

    fn setup_ssl(&self, uri: Uri) -> Result<Ssl, BoxError> {
        let cfg = self.ssl.configure()?;
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);
        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    /// The ALPN protocols a connection for a request forcing `version` offers, encoded.
    fn alpn_offer(&self, version: Option<Version>) -> Option<Bytes> {
        match version {
            // HTTP/1 needs no ALPN, so a connector that offers none keeps offering none.
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => self
                .settings
                .alpn_protocols
                .as_ref()
                .map(|_| AlpnProtocol::HTTP1.encode()),
            Some(Version::HTTP_2) => Some(AlpnProtocol::HTTP2.encode()),
            Some(Version::HTTP_3) => Some(AlpnProtocol::HTTP3.encode()),
            // For unknown versions, we don't set any ALPN protocols.
            Some(_) => None,
            // Default use the connector configuration.
            None => self
                .settings
                .alpn_protocols
                .as_ref()
                .map(|alpn_values| AlpnProtocol::encode_sequence(alpn_values.as_ref())),
        }
    }

    /// The name a connection for `descriptor` verifies, and whether it may announce it
    /// (SNI): the URI host unless the request names another, or announces none.
    fn verified_name(descriptor: &ConnectionDescriptor) -> Result<(&str, bool), BoxError> {
        let host = descriptor.uri().host().ok_or("URI missing host")?;
        let (host, sni) = descriptor.tls_name().unwrap_or((host, true));
        Ok((Self::normalize_host(host), sni))
    }

    /// Whether `stream` can serve `descriptor`'s requests as the connection this connector
    /// would open for it: opened by it, verifying and announcing the same name, accepting
    /// the same leaf certificate should verification fail, and speaking an HTTP version the
    /// request allows — HTTP/2 when its ALPN chose `h2` and the request forces no version,
    /// HTTP/1 when it chose `http/1.1`, `http/1.0` or nothing and the request doesn't force
    /// HTTP/2 or HTTP/3.
    #[cfg(feature = "tokio-rt")]
    pub(crate) fn opened_for<IO>(
        &self,
        stream: &TlsStream<IO>,
        descriptor: &ConnectionDescriptor,
    ) -> Result<bool, BoxError> {
        let (name, sni) = Self::verified_name(descriptor)?;
        let speaks = match stream.stream.ssl().selected_alpn_protocol() {
            Some(b"h2") => descriptor.version().is_none(),
            None | Some(b"http/1.1" | b"http/1.0") => !matches!(
                descriptor.version(),
                Some(Version::HTTP_2 | Version::HTTP_3)
            ),
            Some(_) => false,
        };
        Ok(
            std::ptr::eq(stream.stream.ssl().ssl_context(), self.ssl.context())
                && *stream.name == *name
                && stream.sni == (sni && self.settings.tls_sni)
                && stream.accepted_certificate == descriptor.accepted_certificate()
                && speaks,
        )
    }

    /// The configuration every connection starts with, offering the `alpn` protocols
    /// (encoded; none when `None`).
    fn configure(&self, alpn: Option<&[u8]>) -> Result<ConnectConfiguration, BoxError> {
        let mut cfg = self.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(self.settings.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(self.settings.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(self.settings.enable_ech_grease);

        // Set random AES hardware override
        if self.settings.random_aes_hw_override {
            let random = (crate::util::fast_random() & 1) == 0;
            cfg.set_aes_hw_override(random);
        }

        // Set ALPN protocols
        if let Some(alpn) = alpn {
            cfg.set_alpn_protos(alpn)?;
        }

        // Set ALPS protos
        if let Some(ref alps_values) = self.settings.alps_protocols {
            for alps in alps_values.iter() {
                cfg.add_application_settings(alps.0)?;
            }

            // By default, the new endpoint is used.
            if !alps_values.is_empty() {
                cfg.set_alps_use_new_codepoint(self.settings.alps_use_new_codepoint);
            }
        }

        // Set TLS key shares
        if let Some(ref key_shares) = self.settings.key_shares {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        Ok(cfg)
    }

    fn setup_ssl2(&self, descriptor: ConnectionDescriptor) -> Result<Ssl, BoxError> {
        let cfg = self.configure(self.alpn_offer(descriptor.version()).as_deref())?;
        let (cfg, host, _) = self.for_descriptor(cfg, &descriptor)?;
        Ok(cfg.into_ssl(host)?)
    }

    /// `cfg` made to open `descriptor`'s connection: announcing its name unless it
    /// announces none, accepting the leaf certificate it pins should verification fail, and
    /// offering and keeping the session cached for its connections. Returns the name it
    /// verifies and whether it announces it.
    fn for_descriptor<'a>(
        &self,
        mut cfg: ConnectConfiguration,
        descriptor: &'a ConnectionDescriptor,
    ) -> Result<(ConnectConfiguration, &'a str, bool), BoxError> {
        let (host, sni) = Self::verified_name(descriptor)?;
        if !sni {
            cfg.set_use_server_name_indication(false);
        }

        // Every verification failure, the name's included, goes through the callback.
        if let Some(leaf_sha256) = descriptor.accepted_certificate() {
            let mode = cfg.verify_mode();
            cfg.set_verify_callback(mode, move |verified, ctx| {
                verified
                    || ctx
                        .cert()
                        .and_then(|leaf| leaf.digest(MessageDigest::sha256()).ok())
                        .is_some_and(|digest| *digest == leaf_sha256)
            });
        }

        if let Some(ref cache) = self.cache {
            let key = Key(descriptor.session_id());

            // If the session cache is enabled, we try to retrieve the session
            // associated with the key. If it exists, we set it in the SSL configuration.
            if let Some(session) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session.0) }?;

                if self.settings.no_ticket {
                    cfg.set_options(SslOptions::NO_TICKET);
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        Ok((cfg, host, sni))
    }

    /// Opens a TLS connection over `io` as this connector opens `descriptor`'s, offering
    /// and keeping the same sessions, and offering its ALPN protocols only with `alpn`. A
    /// failed handshake fails with a [`HandshakeFailure`].
    #[cfg(feature = "tokio-rt")]
    pub(crate) async fn connect<IO>(
        &self,
        io: IO,
        descriptor: &ConnectionDescriptor,
        alpn: bool,
        gate: Option<crate::tls::AlpsGate>,
    ) -> Result<TlsStream<IO>, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let offer = alpn
            .then(|| self.alpn_offer(descriptor.version()))
            .flatten();
        let (cfg, name, sni) =
            self.for_descriptor(self.configure(offer.as_deref())?, descriptor)?;
        let mut ssl = cfg.into_ssl(name)?;
        if let Some(gate) = gate {
            aia::set_alps_gate(&mut ssl, gate)?;
        }
        let mut stream = SslStream::new(ssl, io)?;
        if let Err(error) = aia::handshake(&mut stream).await {
            return Err(HandshakeFailure::new(error, stream.ssl()).into());
        }
        Ok(TlsStream {
            stream,
            name: Box::from(name),
            sni: sni && self.settings.tls_sni,
            accepted_certificate: descriptor.accepted_certificate(),
        })
    }

    /// Writes the ClientHello a connection opens with into a peer that never answers,
    /// failing when BoringSSL can't set up the connection or build it.
    fn check(&self) -> Result<(), BoxError> {
        /// A peer that takes every byte and has none to send yet.
        struct Silent;

        impl io::Read for Silent {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        impl io::Write for Silent {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let ssl = self
            .configure(self.alpn_offer(None).as_deref())?
            .into_ssl("example.com")?;
        match ssl.connect(Silent) {
            Err(HandshakeError::WouldBlock(_)) => Ok(()),
            Err(HandshakeError::SetupFailure(err)) => Err(err.into()),
            Err(HandshakeError::Failure(mid)) => Err(mid.into_error().into()),
            Ok(_) => Err("the handshake completed without a peer".into()),
        }
    }

    /// If `host` is an IPv6 address, we must strip away the square brackets that surround
    /// it (otherwise, boring will fail to parse the host as an IP address, eventually
    /// causing the handshake to fail due a hostname verification error).
    fn normalize_host(host: &str) -> &str {
        let normalized = crate::util::strip_ipv6_brackets(host);
        if normalized.len() != host.len() && normalized.parse::<std::net::Ipv6Addr>().is_ok() {
            return normalized;
        }

        host
    }
}

// ====== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Sets the alpn protocol to be used.
    #[inline]
    pub fn alpn_protocol(mut self, protocol: Option<AlpnProtocol>) -> Self {
        self.alpn_protocol = protocol;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the cache of issuers fetched from caIssuers URLs to complete chains missing an
    /// issuer; `None` (the default) fetches none. It applies only with certificate
    /// verification.
    #[inline]
    pub fn aia(mut self, aia: Option<AiaCache>) -> Self {
        self.aia = aia;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Sets a custom TLS session store.
    #[inline]
    pub fn session_store(mut self, store: Option<Arc<dyn TlsSessionCache>>) -> Self {
        if let Some(store) = store {
            self.session_cache = store;
        }
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build<'a, T>(&self, opts: T) -> crate::Result<TlsConnector>
    where
        T: Into<Cow<'a, TlsOptions>>,
    {
        let opts = opts.into();

        // Replace the default configuration with the provided one
        let max_tls_version = opts.max_tls_version.or(self.max_version);
        let min_tls_version = opts.min_tls_version.or(self.min_version);
        let alpn_protocols = self
            .alpn_protocol
            .clone()
            .map(|proto| Cow::Owned(vec![proto]))
            .or_else(|| opts.alpn_protocols.clone());

        // Create the SslConnector with the provided options
        let mut connector = SslConnector::bare_builder(SslMethod::tls())
            .map_err(Error::tls)?
            .set_identity(self.identity.as_ref())?
            .set_cert_store(self.cert_store.as_ref())?
            .set_cert_verification(self.cert_verification)
            .set_aia(self.aia.as_ref().filter(|_| self.cert_verification))
            .set_cert_compressors(opts.certificate_compressors.as_deref())?;

        // Set minimum TLS version
        set_option_inner_try!(min_tls_version, connector, set_min_proto_version);

        // Set maximum TLS version
        set_option_inner_try!(max_tls_version, connector, set_max_proto_version);

        // Set OCSP stapling
        set_bool!(opts, enable_ocsp_stapling, connector, enable_ocsp_stapling);

        // Set Signed Certificate Timestamps (SCT)
        set_bool!(
            opts,
            enable_signed_cert_timestamps,
            connector,
            enable_signed_cert_timestamps
        );

        // Set TLS Session ticket options
        set_bool!(
            opts,
            !session_ticket,
            connector,
            set_options,
            SslOptions::NO_TICKET
        );

        // Set TLS PSK DHE key exchange options
        set_bool!(
            opts,
            !psk_dhe_ke,
            connector,
            set_options,
            SslOptions::NO_PSK_DHE_KE
        );

        // Set TLS No Renegotiation options
        set_bool!(
            opts,
            !renegotiation,
            connector,
            set_options,
            SslOptions::NO_RENEGOTIATION
        );

        // Set TLS grease options
        set_option!(opts, grease_enabled, connector, set_grease_enabled);
        connector.set_grease_signature_algorithms(opts.grease_signature_algorithms);

        // Set TLS permute extensions options
        set_option!(opts, permute_extensions, connector, set_permute_extensions);

        // Set TLS curves list
        set_option_ref_try!(opts, curves_list, connector, set_curves_list);

        // Set TLS signature algorithms list
        set_option_ref_try!(opts, sigalgs_list, connector, set_sigalgs_list);

        // Set TLS prreserve TLS 1.3 cipher list order
        set_option!(
            opts,
            preserve_tls13_cipher_list,
            connector,
            set_preserve_tls13_cipher_list
        );

        // Set TLS cipher list
        set_option_ref_try!(opts, cipher_list, connector, set_cipher_list);

        // Set TLS delegated credentials
        set_option_ref_try!(
            opts,
            delegated_credentials,
            connector,
            set_delegated_credentials
        );

        // Set TLS record size limit
        set_option!(opts, record_size_limit, connector, set_record_size_limit);

        // Set TLS aes hardware override
        set_option!(opts, aes_hw_override, connector, set_aes_hw_override);

        // Set TLS extension permutation
        if let Some(ref extension_permutation) = opts.extension_permutation {
            connector
                .set_extension_permutation(extension_permutation)
                .map_err(Error::tls)?;
        }

        // Set whether the extension permutation is the whole extension list
        connector.set_strict_extension_order(opts.strict_extension_order);
        connector.set_padding_length(opts.padding_length);

        // Set TLS renegotiation signalling cipher suite value
        connector.set_renegotiation_scsv(opts.renegotiation_scsv);

        // Set TLS trust anchor IDs
        set_option_ref_try!(opts, trust_anchors, connector, set_requested_trust_anchors);

        // Set the legacy session ID length
        connector
            .set_session_id_length(opts.session_id_length)
            .map_err(Error::tls)?;

        // Set the GREASE ECH extension's payload length and cipher suite
        connector
            .set_ech_grease_payload_length(opts.ech_grease_payload_length)
            .map_err(Error::tls)?;
        connector.set_ech_grease_cipher_suite(opts.ech_grease_cipher_suite);

        // Keep each connection's ClientHello for its `TlsInfo`.
        // SAFETY: `connector` owns a live `SSL_CTX`; the callback is a plain function.
        #[allow(unsafe_code)]
        unsafe {
            btls_sys::SSL_CTX_set_msg_callback(connector.as_ptr(), Some(record_handshake_message));
        }

        // Set TLS keylog handler.
        if let Some(ref policy) = self.keylog {
            let handle = policy.clone().handle().map_err(Error::tls)?;
            connector.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        // Create the handshake settings with the default session cache capacity.
        let settings = HandshakeSettings {
            tls_sni: self.tls_sni,
            verify_hostname: self.verify_hostname,
            no_ticket: opts.psk_skip_session_ticket,
            alpn_protocols,
            alps_protocols: opts.alps_protocols.clone(),
            alps_use_new_codepoint: opts.alps_use_new_codepoint,
            enable_ech_grease: opts.enable_ech_grease,
            key_shares: opts.key_shares.clone(),
            random_aes_hw_override: opts.random_aes_hw_override,
        };

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.pre_shared_key.then(|| {
            let session_cache = self.session_cache.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = session_cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.put(
                            key.clone(),
                            TlsSession(session, peer_quic_transport_parameters(ssl)),
                        );
                    }
                }
            });

            session_cache
        });

        let connector = TlsConnector {
            ssl: connector.build(),
            cache,
            settings,
        };
        connector.check().map_err(Error::tls)?;
        Ok(connector)
    }
}

/// The transport parameters the server of a QUIC connection sent, as it encoded them; `None`
/// for a TLS connection over TCP.
#[allow(unsafe_code)]
fn peer_quic_transport_parameters(ssl: &SslRef) -> Option<Bytes> {
    // SAFETY: `ssl` is a live `SSL`; BoringSSL points `params` at `len` bytes it owns, valid
    // until the connection changes, and they are copied at once.
    unsafe {
        let ssl = foreign_types::ForeignTypeRef::as_ptr(ssl);
        if btls_sys::SSL_is_quic(ssl) == 0 {
            return None;
        }
        let mut params = std::ptr::null();
        let mut len = 0;
        btls_sys::SSL_get_peer_quic_transport_params(ssl, &mut params, &mut len);
        (!params.is_null()).then(|| Bytes::copy_from_slice(std::slice::from_raw_parts(params, len)))
    }
}

/// A TLS connector for QUIC handshakes a caller drives: each [`Ssl`] it makes offers the
/// ClientHello its [`TlsOptions`] describe, as a client's TCP connections do, and verifies
/// the server against the same trust. The caller adds the QUIC transport (its method and
/// transport parameters) to each.
///
/// With [`TlsOptions::pre_shared_key`], its connections keep the sessions they receive in its
/// session store, with the server's transport parameters, and resume them (see
/// [`QuicTlsConnector::new_ssl`]).
#[derive(Clone)]
pub struct QuicTlsConnector(TlsConnector);

/// A client [`Ssl`] for one QUIC connection (see [`QuicTlsConnector::new_ssl`]).
pub struct QuicSsl {
    /// The connection's TLS, to which the caller adds the QUIC transport.
    pub ssl: Ssl,
    /// When `ssl` resumes a session, the transport parameters the server sent on the
    /// connection that received it, as it encoded them: a client sending 0-RTT data keeps to
    /// them.
    pub resumed_transport_parameters: Option<Bytes>,
}

/// Builds a [`QuicTlsConnector`].
pub struct QuicTlsConnectorBuilder(TlsConnectorBuilder);

impl QuicTlsConnector {
    /// Creates a [`QuicTlsConnectorBuilder`].
    pub fn builder() -> QuicTlsConnectorBuilder {
        QuicTlsConnectorBuilder(TlsConnector::builder())
    }

    /// A client [`Ssl`] for one QUIC connection verifying `name`, announcing it (SNI) when
    /// `sni`.
    ///
    /// With `origin` (an `https` URI with the origin's host and port), and a session store,
    /// the connection offers the session the store gives for the origin, `name` and `sni`, if
    /// any, and keeps those it receives there.
    pub fn new_ssl(&self, name: &str, sni: bool, origin: Option<&Uri>) -> crate::Result<QuicSsl> {
        let mut cfg = self
            .0
            .configure(self.0.alpn_offer(None).as_deref())
            .map_err(Error::tls)?;
        if !sni {
            cfg.set_use_server_name_indication(false);
        }
        let name = TlsConnector::normalize_host(name);
        let mut resumed_transport_parameters = None;
        if let (Some(cache), Some(origin)) = (&self.0.cache, origin) {
            let key = Key::quic(origin, name, sni);
            if let Some(TlsSession(session, params)) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session) }.map_err(Error::tls)?;
                resumed_transport_parameters = params;
            }
            cfg.set_ex_data(key_index().map_err(Error::tls)?, key);
        }
        let ssl = cfg.into_ssl(name).map_err(Error::tls)?;
        Ok(QuicSsl {
            ssl,
            resumed_transport_parameters,
        })
    }
}

impl QuicTlsConnectorBuilder {
    /// Sets the certificate store the server is verified against.
    pub fn cert_store<T>(self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        Self(self.0.cert_store(cert_store))
    }

    /// Sets whether the server's certificate is verified.
    pub fn cert_verification(self, enabled: bool) -> Self {
        Self(self.0.cert_verification(enabled))
    }

    /// Sets the identity for client certificate authentication.
    pub fn identity(self, identity: Option<Identity>) -> Self {
        Self(self.0.identity(identity))
    }

    /// Sets the TLS keylog policy.
    pub fn keylog(self, keylog: Option<KeyLog>) -> Self {
        Self(self.0.keylog(keylog))
    }

    /// Sets the store keeping the connections' sessions.
    pub fn session_store(self, store: Option<Arc<dyn TlsSessionCache>>) -> Self {
        Self(self.0.session_store(store))
    }

    /// Builds the connector, failing when BoringSSL can't write the ClientHello `opts`
    /// describe.
    pub fn build<'a, T>(&self, opts: T) -> crate::Result<QuicTlsConnector>
    where
        T: Into<Cow<'a, TlsOptions>>,
    {
        self.0.build(opts).map(QuicTlsConnector)
    }
}

/// A TLS connection a client opened over a caller's stream (see
/// [`Client::tls_connect`](crate::Client::tls_connect)).
pub struct TlsStream<IO> {
    pub(crate) stream: SslStream<IO>,
    /// The name it verified, and whether it announced it.
    name: Box<str>,
    #[cfg_attr(not(feature = "tokio-rt"), allow(dead_code))]
    sni: bool,
    /// The SHA-256 of the leaf certificate it accepts should verification fail.
    #[cfg_attr(not(feature = "tokio-rt"), allow(dead_code))]
    accepted_certificate: Option<[u8; 32]>,
}

impl<IO> TlsStream<IO> {
    /// The negotiated TLS of this connection, with the ClientHello it sent.
    pub fn tls_info(&self) -> TlsInfo {
        self.stream.tls_info().expect("TLS info of a TLS stream")
    }

    /// The stream the connection runs over.
    pub fn get_ref(&self) -> &IO {
        self.stream.get_ref()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Whether the peer has neither closed the connection nor sent data yet, reading
    /// only what is already there (a TLS 1.3 session ticket, say).
    #[cfg(feature = "tokio-rt")]
    pub(crate) fn idle(&mut self) -> bool {
        let mut byte = [0; 1];
        Pin::new(&mut self.stream)
            .poll_read(
                &mut Context::from_waker(std::task::Waker::noop()),
                &mut ReadBuf::new(&mut byte),
            )
            .is_pending()
    }
}

/// Why a TLS handshake a client opened over a caller's stream failed (see
/// [`RequestBuilder::tls_connect`](crate::RequestBuilder::tls_connect)): what the peer
/// ended it with, and what it presented.
#[derive(Debug)]
pub struct HandshakeFailure {
    error: btls::ssl::Error,
    alert: Option<u8>,
    verify_error: Option<(i32, &'static str)>,
    peer_certificate_chain: Vec<Bytes>,
    version: &'static str,
    cipher: Option<&'static str>,
    alpn_protocol: Option<Bytes>,
    group: Option<u16>,
    hello_retry_request: bool,
    aia_fetches: Vec<AiaFetch>,
    server_flight: Option<crate::tls::ServerFlight>,
    peer_ocsp: Option<Bytes>,
}

impl HandshakeFailure {
    #[cfg_attr(not(feature = "tokio-rt"), allow(dead_code))]
    fn new(error: btls::ssl::Error, ssl: &SslRef) -> Self {
        // A received alert is reported as the SSL library's reason `SSL_AD_REASON_OFFSET`
        // plus its description.
        let alert = error.ssl_error().and_then(|stack| {
            stack.errors().iter().find_map(|error| {
                let reason = error.library_reason(btls_sys::ERR_LIB_SSL)?;
                u8::try_from(reason.checked_sub(btls_sys::SSL_AD_REASON_OFFSET)?).ok()
            })
        });
        let verify_error = aia::verify_result(ssl)
            .err()
            .map(|error| (error.as_raw(), error.error_string()));
        let peer_certificate_chain = ssl
            .peer_cert_chain()
            .into_iter()
            .flatten()
            .filter_map(|cert| cert.to_der().ok().map(Bytes::from))
            .collect();
        Self {
            error,
            alert,
            verify_error,
            peer_certificate_chain,
            version: ssl.version_str(),
            cipher: ssl
                .current_cipher()
                .map(|cipher| cipher.standard_name().unwrap_or_else(|| cipher.name())),
            alpn_protocol: ssl.selected_alpn_protocol().map(Bytes::copy_from_slice),
            group: ssl.curve(),
            hello_retry_request: ssl.used_hello_retry_request(),
            aia_fetches: aia::fetches(ssl),
            server_flight: server_flight_index()
                .ok()
                .and_then(|index| ssl.ex_data(index))
                .map(|messages| crate::tls::ServerFlight::from(messages.lock().clone())),
            peer_ocsp: ssl.ocsp_status().map(Bytes::copy_from_slice),
        }
    }

    /// The alert the peer ended the handshake with, if it sent one.
    pub fn alert(&self) -> Option<u8> {
        self.alert
    }

    /// Why the peer's certificate failed verification, if it did: the `X509_V_ERR_*` code
    /// and its description.
    pub fn verify_error(&self) -> Option<(i32, &'static str)> {
        self.verify_error
    }

    /// The DER certificate chain the peer presented, leaf first; empty if it sent none.
    pub fn peer_certificate_chain(&self) -> impl Iterator<Item = &[u8]> {
        self.peer_certificate_chain.iter().map(|cert| cert.as_ref())
    }

    /// The protocol version the handshake got as far as negotiating, e.g. `TLSv1.3`.
    pub fn version(&self) -> &str {
        self.version
    }

    /// The cipher suite the handshake got as far as negotiating, by its standard (RFC)
    /// name when it has one.
    pub fn cipher(&self) -> Option<&str> {
        self.cipher
    }

    /// The protocol the peer selected through ALPN, if it got as far as selecting one.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// The key exchange group the handshake got as far as negotiating, by its TLS id.
    pub fn group(&self) -> Option<u16> {
        self.group
    }

    /// Whether the server answered the first ClientHello with a HelloRetryRequest.
    pub fn hello_retry_request(&self) -> bool {
        self.hello_retry_request
    }

    /// The origin's server flight as far as it got (see [`crate::tls::ServerFlight`]).
    pub fn server_flight(&self) -> Option<&crate::tls::ServerFlight> {
        self.server_flight.as_ref()
    }

    /// The DER OCSP response the origin stapled, if it did and stapling was requested.
    pub fn peer_ocsp(&self) -> Option<&[u8]> {
        self.peer_ocsp.as_deref()
    }

    /// The caIssuers URLs whose issuers the certificate verification needed (see
    /// [`AiaCache`]), in the order it needed them.
    pub fn aia_fetches(&self) -> &[AiaFetch] {
        &self.aia_fetches
    }
}

impl fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for HandshakeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl<IO: fmt::Debug> fmt::Debug for TlsStream<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", self.stream.get_ref())
            .field("name", &self.name)
            .finish()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A connection offered to a request's connection attempt, which takes it.
#[cfg(feature = "tokio-rt")]
#[derive(Clone)]
pub(crate) enum Preconnected {
    /// An established TLS connection to adopt as it is (see
    /// [`RequestBuilder::adopt`](crate::RequestBuilder::adopt)).
    Adopt(Offer<TlsStream<tokio::net::TcpStream>>),
    /// A TCP connection that TLS runs over like a newly opened one (see
    /// [`RequestBuilder::connect_over`](crate::RequestBuilder::connect_over)).
    Over(Offer<tokio::net::TcpStream>),
}

/// An offered connection, until a connection attempt takes it.
#[cfg(feature = "tokio-rt")]
pub(crate) struct Offer<T>(Arc<std::sync::Mutex<Option<T>>>);

#[cfg(feature = "tokio-rt")]
impl<T> Clone for Offer<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[cfg(feature = "tokio-rt")]
impl<T> Offer<T> {
    pub(crate) fn new(connection: T) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(connection))))
    }

    /// The connection, unless a connection attempt took it already.
    pub(crate) fn take(&self) -> Option<T> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

#[cfg(feature = "tokio-rt")]
impl fmt::Debug for Preconnected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Preconnected(..)")
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

/// A connection that has been established with a TLS handshake.
pub struct EstablishedConn<IO> {
    io: IO,
    descriptor: ConnectionDescriptor,
}

// ===== impl MaybeHttpsStream =====

impl<T> AsRef<T> for MaybeHttpsStream<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        match self {
            MaybeHttpsStream::Http(s) => s,
            MaybeHttpsStream::Https(s) => s.get_ref(),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    #[inline]
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => s.get_ref().connected(),
        }
    }
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_read(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write(ctx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write(ctx, buf),
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(ctx),
        }
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_shutdown(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_shutdown(ctx),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(inner) => inner.is_write_vectored(),
            MaybeHttpsStream::Https(inner) => inner.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }
}

// ===== impl EstablishedConn =====

impl<IO> EstablishedConn<IO> {
    /// Creates a new [`EstablishedConn`].
    #[inline]
    pub fn new(io: IO, descriptor: ConnectionDescriptor) -> EstablishedConn<IO> {
        EstablishedConn { io, descriptor }
    }
}
