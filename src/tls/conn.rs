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
        ClientHelloList, ConnectConfiguration, HandshakeError, Ssl, SslConnector, SslMethod,
        SslOptions, SslRef, SslSessionCacheMode,
    },
};
use bytes::Bytes;
use ext::SslConnectorBuilderExt;
use http::{Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

use crate::{
    Error, Group,
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
/// NewSessionTickets arrive after the handshake, once the connection is in use (see
/// [`keeps`]).
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
    // The origin's server flight, kept in order (see `keeps`).
    let Ok(index) = server_flight_index() else {
        return;
    };
    let record = || bytes::Bytes::copy_from_slice(message);
    if let Some(flight) = ssl.ex_data(index) {
        let mut flight = flight.lock();
        let late = flight.iter().any(|msg| msg.first() == Some(&FINISHED));
        if keeps(&flight, message[0]) {
            flight.push(record());
        }
        drop(flight);
        if late && let Some(gate) = aia::alps_gate(ssl) {
            gate.note_post_handshake_message();
            if message[0] == CERTIFICATE_REQUEST {
                gate.note_late_certificate_request();
            }
        }
    } else {
        ssl.set_ex_data(index, Arc::new(crate::sync::Mutex::new(vec![record()])));
    }
}

/// The most NewSessionTickets a server flight keeps: BoringSSL's servers send at most 16.
const MAX_FLIGHT_TICKETS: usize = 16;

const CERTIFICATE_REQUEST: u8 = 13;
const FINISHED: u8 = 20;

/// Whether a server `flight` keeps a handshake message of type `kind` the server sent next.
/// Past its handshake (its Finished), a server may send handshake messages for the
/// connection's whole life, so only the first NewSessionTickets and a CertificateRequest
/// (post-handshake authentication, or a renegotiation's) if it has none are kept.
fn keeps(flight: &[bytes::Bytes], kind: u8) -> bool {
    const NEW_SESSION_TICKET: u8 = 4;
    let count = |kind| {
        flight
            .iter()
            .filter(|msg| msg.first() == Some(&kind))
            .count()
    };
    count(FINISHED) == 0
        || match kind {
            NEW_SESSION_TICKET => count(NEW_SESSION_TICKET) < MAX_FLIGHT_TICKETS,
            CERTIFICATE_REQUEST => count(CERTIFICATE_REQUEST) == 0,
            _ => false,
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
    renegotiation: bool,
    hello_record_version: Option<u16>,
    hello_record_layout: Option<Cow<'static, [u16]>>,
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
    /// the same leaf certificate should verification fail, with a DHE group, if its session
    /// has one, of a size the request accepts, and speaking an HTTP version the
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
                && stream
                    .stream
                    .ssl()
                    .session()
                    .and_then(|session| session.dhe_bits())
                    .is_none_or(|bits| bits >= descriptor.min_dhe_bits().unwrap_or(2048))
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

        // Take the server's TLS 1.2 renegotiation when offering secure renegotiation
        set_renegotiation(&cfg, self.settings.renegotiation);

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
    /// announces none, accepting the DHE groups it accepts and the leaf certificate it pins
    /// should verification fail, and
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

        if let Some(bits) = descriptor.min_dhe_bits() {
            cfg.set_min_dhe_bits(bits)?;
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
        let io = HelloRecords::new(io, &self.settings);
        let mut stream = SslStream::new(ssl, io)?;
        if let Err(error) = aia::handshake(&mut stream).await {
            return Err(HandshakeFailure::new(error, stream.ssl()).into());
        }
        forbid_http2_renegotiation(stream.ssl());
        Ok(TlsStream {
            accepted_certificate: descriptor
                .accepted_certificate()
                .or_else(|| aia::accepted_certificate(stream.ssl())),
            stream,
            name: Box::from(name),
            sni: sni && self.settings.tls_sni,
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

        // Set TLS max fragment length
        set_option!(opts, max_fragment_length, connector, set_max_fragment_length);

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
        connector.set_post_handshake_auth(opts.post_handshake_auth);
        connector.set_padding_length(opts.padding_length);

        // Set the ClientHello's offered lists
        let point_formats = opts
            .offered_point_formats
            .as_deref()
            .map(|formats| formats.iter().copied().map(u16::from).collect::<Vec<_>>());
        for (list, values) in [
            (
                ClientHelloList::CIPHER_SUITES,
                opts.offered_cipher_suites.as_deref(),
            ),
            (
                ClientHelloList::SUPPORTED_GROUPS,
                opts.offered_groups.as_deref(),
            ),
            (
                ClientHelloList::KEY_SHARES,
                opts.offered_key_shares.as_deref(),
            ),
            (
                ClientHelloList::SUPPORTED_VERSIONS,
                opts.offered_versions.as_deref(),
            ),
            (
                ClientHelloList::SIGNATURE_ALGORITHMS,
                opts.offered_sigalgs.as_deref(),
            ),
            (
                ClientHelloList::SIGNATURE_ALGORITHMS_CERT,
                opts.offered_sigalgs_cert.as_deref(),
            ),
            (ClientHelloList::EC_POINT_FORMATS, point_formats.as_deref()),
        ] {
            connector
                .set_client_hello_list(list, values)
                .map_err(Error::tls)?;
        }

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
            renegotiation: opts.renegotiation || opts.renegotiation_scsv,
            hello_record_version: opts.hello_record_version,
            hello_record_layout: opts.hello_record_layout.clone(),
        };

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.pre_shared_key.then(|| {
            let session_cache = self.session_cache.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = session_cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        // A certificate failing verification that the connection's gate
                        // accepted is trusted only by the connections accepting it.
                        let key = match aia::accepted_certificate(ssl) {
                            Some(leaf_sha256) => key.accepting(leaf_sha256),
                            None => key.clone(),
                        };
                        cache.put(
                            key,
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

/// Sets whether `ssl`, a client, takes the server's TLS 1.2 renegotiations, as browsers
/// offering secure renegotiation do on HTTP/1, or refuses them (BoringSSL's default).
#[allow(unsafe_code)]
fn set_renegotiation(ssl: &SslRef, freely: bool) {
    let mode = if freely {
        btls_sys::ssl_renegotiate_mode_t::ssl_renegotiate_freely
    } else {
        btls_sys::ssl_renegotiate_mode_t::ssl_renegotiate_never
    };
    // SAFETY: `ssl` is a live `SSL`, and the mode is a setting it reads when the server
    // starts a renegotiation.
    unsafe { btls_sys::SSL_set_renegotiate_mode(foreign_types::ForeignTypeRef::as_ptr(ssl), mode) }
}

/// Refuses renegotiation on `ssl`, a connection whose handshake completed, once it speaks
/// HTTP/2, which forbids it (RFC 9113 §9.2.1).
pub(crate) fn forbid_http2_renegotiation(ssl: &SslRef) {
    if ssl.selected_alpn_protocol() == Some(b"h2") {
        set_renegotiation(ssl, false);
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
    /// The server flight `ssl`'s handshake receives.
    pub server_flight: QuicServerFlight,
}

/// The server flight a QUIC connection's handshake received so far (see [`QuicSsl`]).
#[derive(Clone)]
pub struct QuicServerFlight(SharedFlight);

impl QuicServerFlight {
    /// The messages received so far (see [`crate::tls::ServerFlight`]).
    pub fn get(&self) -> crate::tls::ServerFlight {
        crate::tls::ServerFlight::from(self.0.lock().clone())
    }
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
    /// the connection offers the session the store gives for the origin, `name`, `sni` and
    /// `group` (which partitions the sessions as a request's [`Group`] does), if any, and
    /// keeps those it receives there.
    pub fn new_ssl(
        &self,
        name: &str,
        sni: bool,
        origin: Option<&Uri>,
        group: Option<Group>,
    ) -> crate::Result<QuicSsl> {
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
            let key = Key::quic(origin, name, sni, group);
            if let Some(TlsSession(session, params)) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session) }.map_err(Error::tls)?;
                resumed_transport_parameters = params;
            }
            cfg.set_ex_data(key_index().map_err(Error::tls)?, key);
        }
        let server_flight = SharedFlight::default();
        cfg.set_ex_data(
            server_flight_index().map_err(Error::tls)?,
            Arc::clone(&server_flight),
        );
        let ssl = cfg.into_ssl(name).map_err(Error::tls)?;
        Ok(QuicSsl {
            ssl,
            resumed_transport_parameters,
            server_flight: QuicServerFlight(server_flight),
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
    pub(crate) stream: SslStream<HelloRecords<IO>>,
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
        &self.stream.get_ref().io
    }

    /// Whether the peer closed its TLS with a close_notify: a read ending without one ends
    /// as one ending with one does.
    pub fn received_close_notify(&self) -> bool {
        self.stream
            .ssl()
            .get_shutdown()
            .contains(btls::ssl::ShutdownState::RECEIVED)
    }
}

/// The alert the peer sent that `error` reports, if it does: the SSL library's reason for it
/// is `SSL_AD_REASON_OFFSET` plus its description.
pub(crate) fn received_alert(error: &btls::ssl::Error) -> Option<u8> {
    error.ssl_error()?.errors().iter().find_map(|error| {
        let reason = error.library_reason(btls_sys::ERR_LIB_SSL)?;
        u8::try_from(reason.checked_sub(btls_sys::SSL_AD_REASON_OFFSET)?).ok()
    })
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Sends the fatal TLS alert `alert`, past which the connection sends nothing.
    pub fn poll_send_fatal_alert(
        &mut self,
        cx: &mut Context<'_>,
        alert: u8,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_send_fatal_alert(cx, alert)
            .map_err(io::Error::other)
    }

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
    server_end: Option<aia::ServerEnd>,
    alert: Option<u8>,
    verify_error: Option<(i32, &'static str)>,
    peer_certificate_chain: Vec<Bytes>,
    version: &'static str,
    cipher: Option<&'static str>,
    alpn_protocol: Option<Bytes>,
    group: Option<u16>,
    hello_retry_request: bool,
    aia_fetches: Vec<AiaFetch>,
    verified_path: Vec<Bytes>,
    server_flight: Option<crate::tls::ServerFlight>,
    peer_ocsp: Option<Bytes>,
}

impl HandshakeFailure {
    #[cfg_attr(not(feature = "tokio-rt"), allow(dead_code))]
    fn new(error: btls::ssl::Error, ssl: &SslRef) -> Self {
        let server_end = aia::server_end_of(ssl);
        // A received alert is reported as the SSL library's reason `SSL_AD_REASON_OFFSET`
        // plus its description.
        let alert = match &server_end {
            Some(aia::ServerEnd::Alert { description, .. }) => Some(*description),
            _ => received_alert(&error),
        };
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
            server_end,
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
            verified_path: aia::verified_path(ssl).unwrap_or_default(),
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

    /// What the server selected that the ClientHello only offered (see
    /// [`TlsOptions::offered_cipher_suites`](crate::tls::TlsOptions::offered_cipher_suites)),
    /// e.g. `cipher suite 0041`, if that ended the handshake.
    pub fn offer_only_selection(&self) -> Option<&str> {
        self.error.ssl_error()?.errors().iter().find_map(|error| {
            (error.library_reason(btls_sys::ERR_LIB_SSL)?
                == btls_sys::SSL_R_OFFER_ONLY_VALUE_SELECTED)
                .then(|| error.data().unwrap_or_default())
        })
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

    /// The certification path verifying the server certificate built, leaf first (DER), as
    /// far as it got; empty when verification never ran or the client verifies without an
    /// [`AiaCache`] (see [`ClientBuilder::tls_aia`](crate::ClientBuilder::tls_aia)).
    pub fn verified_path(&self) -> impl Iterator<Item = &[u8]> {
        self.verified_path.iter().map(|cert| cert.as_ref())
    }
}

impl fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.server_end {
            Some(aia::ServerEnd::Alert { level, description }) => write!(
                f,
                "the server sent alert {description} (level {level}) while the handshake waited"
            ),
            Some(aia::ServerEnd::Io(error)) => {
                write!(
                    f,
                    "the server ended the connection while the handshake waited: {error}"
                )
            }
            None => fmt::Display::fmt(&self.error, f),
        }
    }
}

impl std::error::Error for HandshakeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.server_end {
            Some(aia::ServerEnd::Io(error)) => Some(error),
            // Its error only tells the handshake paused; the server's alert ended it.
            Some(aia::ServerEnd::Alert { .. }) => None,
            None => Some(&self.error),
        }
    }
}

impl<IO: fmt::Debug> fmt::Debug for TlsStream<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", self.get_ref())
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

/// The stream a TLS connection runs over, writing the records it sends before the
/// server's first byte (its ClientHello) with `version` as their record version, rather
/// than the TLS 1.0 BoringSSL writes them with, and the ClientHello in records of the
/// `layout` lengths (see [`TlsOptions::hello_record_layout`]), the second one answering a
/// HelloRetryRequest too, as a client fragments both alike.
pub struct HelloRecords<IO> {
    io: IO,
    version: Option<[u8; 2]>,
    framing: Framing,
    /// The ClientHello's record layout.
    layout: Option<Cow<'static, [u16]>>,
    /// Whether the next ClientHello goes out in `layout`'s records: the first, and the
    /// second once the server's first message was a HelloRetryRequest.
    relaying: bool,
    /// The server's first bytes, while they may yet show a HelloRetryRequest.
    server_head: Option<Vec<u8>>,
    /// The ClientHello's records as written, held until the ClientHello is complete.
    held: Vec<u8>,
    /// Bytes accepted but not yet written to `io`, from `sent` on.
    pending: Vec<u8>,
    sent: usize,
    /// What the server sent, read ahead of the TLS library while its handshake waits (see
    /// [`Self::poll_read_ahead`]), for it to read first.
    ahead: Vec<u8>,
}

/// Where the next byte written falls: in a record's header (of a `kind` record), or
/// `fragment` bytes of its fragment before the next header.
#[derive(Clone, Copy, Default)]
struct Framing {
    header: usize,
    kind: u8,
    length: u8,
    fragment: usize,
}

impl Framing {
    /// Sets the record version of every handshake record's header in `bytes`, the next
    /// ones written.
    fn frame(&mut self, version: [u8; 2], bytes: &mut [u8]) {
        let mut at = 0;
        while at < bytes.len() {
            if self.fragment > 0 {
                let skipped = self.fragment.min(bytes.len() - at);
                self.fragment -= skipped;
                at += skipped;
                continue;
            }
            match self.header {
                0 => self.kind = bytes[at],
                1 | 2 if self.kind == 0x16 => bytes[at] = version[self.header - 1],
                3 => self.length = bytes[at],
                4 => self.fragment = usize::from(u16::from_be_bytes([self.length, bytes[at]])),
                _ => {}
            }
            self.header = (self.header + 1) % 5;
            at += 1;
        }
    }
}

/// The largest fragment a TLS record carries (RFC 8446 §5.1).
const MAX_FRAGMENT: usize = 1 << 14;

/// The bytes of a ServerHello up to the end of its random: the handshake header, the
/// version and the random.
const SERVER_HELLO_RANDOM_END: usize = 4 + 2 + 32;

/// How many of the server's first bytes may show its ServerHello's random: as many as
/// records carrying a byte of it each take.
const SERVER_HEAD_LIMIT: usize = SERVER_HELLO_RANDOM_END * (5 + 1);

impl<IO> HelloRecords<IO> {
    fn new(io: IO, settings: &HandshakeSettings) -> Self {
        let layout = settings
            .hello_record_layout
            .clone()
            .filter(|layout| !layout.is_empty());
        Self {
            io,
            version: settings.hello_record_version.map(u16::to_be_bytes),
            framing: Framing::default(),
            relaying: layout.is_some(),
            server_head: layout.as_ref().map(|_| Vec::new()),
            layout,
            held: Vec::new(),
            pending: Vec::new(),
            sent: 0,
            ahead: Vec::new(),
        }
    }

    /// Reads what the server sends next ahead of the TLS library, which reads it first once
    /// it reads again (see [`Self::read_ahead`]): how many bytes, none at EOF.
    pub(crate) fn poll_read_ahead(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        IO: AsyncRead + Unpin,
    {
        let mut chunk = [0; 4096];
        let mut buf = ReadBuf::new(&mut chunk);
        std::task::ready!(self.poll_read_io(cx, &mut buf))?;
        self.ahead.extend_from_slice(buf.filled());
        Poll::Ready(Ok(buf.filled().len()))
    }

    /// What [`Self::poll_read_ahead`] read that the TLS library hasn't yet.
    pub(crate) fn read_ahead(&self) -> &[u8] {
        &self.ahead
    }

    /// Reads from `io` into `buf`, taking note of the server's first bytes.
    fn poll_read_io(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>
    where
        IO: AsyncRead + Unpin,
    {
        let filled = buf.filled().len();
        let read = Pin::new(&mut self.io).poll_read(cx, buf);
        if buf.filled().len() > filled {
            self.version = None;
            self.read_server_head(&buf.filled()[filled..]);
        }
        read
    }

    /// Takes `read`, the server's next bytes, until they show whether its first message is a
    /// HelloRetryRequest, which the second ClientHello answers.
    fn read_server_head(&mut self, read: &[u8]) {
        let Some(head) = &mut self.server_head else {
            return;
        };
        let take = read.len().min(SERVER_HEAD_LIMIT - head.len());
        head.extend_from_slice(&read[..take]);
        // The ServerHello as far as its handshake records carry it, which a server may
        // fragment across them.
        let mut hello = Vec::new();
        let mut records = head.as_slice();
        let mut other = false;
        while hello.len() < SERVER_HELLO_RANDOM_END
            && let Some((header, rest)) = records.split_first_chunk::<5>()
        {
            if header[0] != 0x16 {
                other = true;
                break;
            }
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            hello.extend_from_slice(&rest[..length.min(rest.len())]);
            records = rest.get(length..).unwrap_or_default();
        }
        if hello.len() < SERVER_HELLO_RANDOM_END && !other && head.len() < SERVER_HEAD_LIMIT {
            return;
        }
        self.relaying = hello.len() >= SERVER_HELLO_RANDOM_END
            && hello[0] == 2
            && hello[6..SERVER_HELLO_RANDOM_END] == crate::tls::ServerFlight::HRR_RANDOM;
        self.server_head = None;
    }

    /// Moves `bytes`, records written after the ClientHello's, to `pending`, with
    /// `version` set on their handshake records.
    fn pass(&mut self, mut bytes: Vec<u8>) {
        if let Some(version) = self.version {
            self.framing.frame(version, &mut bytes);
        }
        self.pending.extend_from_slice(&bytes);
    }

    /// Once `held` carries the whole ClientHello, queues it in the layout's records (and
    /// whatever was written before and after it as written). A write `held` can't be the
    /// ClientHello's records in goes out as written.
    fn relayout(&mut self) {
        let Some(layout) = self.layout.as_deref() else {
            return;
        };
        // Records ahead of the ClientHello (a ChangeCipherSpec before a second one).
        let mut ahead = 0;
        while let Some(header) = self.held.get(ahead..ahead + 5)
            && header[0] != 0x16
        {
            ahead += 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
        }
        if ahead > self.held.len() {
            return;
        }
        let mut hello = Vec::new();
        let mut at = ahead;
        let mut record_version = [3, 1];
        let complete = loop {
            let Some(header) = self.held.get(at..at + 5) else {
                break false;
            };
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if header[0] != 0x16 {
                break true;
            }
            record_version = [header[1], header[2]];
            let Some(fragment) = self.held.get(at + 5..at + 5 + length) else {
                break false;
            };
            hello.extend_from_slice(fragment);
            at += 5 + length;
            if hello.len() >= 4
                && hello.len()
                    >= 4 + usize::from(hello[1]) * 65536
                        + usize::from(u16::from_be_bytes([hello[2], hello[3]]))
            {
                break true;
            }
        };
        if !complete {
            return;
        }
        let version = self.version.unwrap_or(record_version);
        let mut records = Vec::new();
        let mut rest = hello.as_slice();
        let mut lengths = layout.iter().map(|&length| usize::from(length));
        while !rest.is_empty() {
            let length = lengths.next().unwrap_or(MAX_FRAGMENT).min(rest.len());
            let (fragment, after) = rest.split_at(length);
            records.push(0x16);
            records.extend_from_slice(&version);
            records.extend_from_slice(&(length as u16).to_be_bytes());
            records.extend_from_slice(fragment);
            rest = after;
        }
        self.relaying = false;
        let after = self.held.split_off(at);
        let mut ahead_records = std::mem::take(&mut self.held);
        ahead_records.truncate(ahead);
        self.pass(ahead_records);
        self.pending.extend_from_slice(&records);
        self.pass(after);
    }

    /// Writes `pending` to `io`.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        IO: AsyncWrite + Unpin,
    {
        while self.sent < self.pending.len() {
            let written = std::task::ready!(
                Pin::new(&mut self.io).poll_write(cx, &self.pending[self.sent..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += written;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<IO: Connection> Connection for HelloRecords<IO> {
    fn connected(&self) -> Connected {
        self.io.connected()
    }

    fn socket(&self) -> Option<socket2::SockRef<'_>> {
        self.io.socket()
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for HelloRecords<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.ahead.is_empty() {
            let len = self.ahead.len().min(buf.remaining());
            buf.put_slice(&self.ahead[..len]);
            self.ahead.drain(..len);
            return Poll::Ready(Ok(()));
        }
        self.get_mut().poll_read_io(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for HelloRecords<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_send(cx))?;
        if self.relaying {
            self.held.extend_from_slice(buf);
            self.relayout();
            return Poll::Ready(Ok(buf.len()));
        }
        let Some(version) = self.version else {
            return Pin::new(&mut self.io).poll_write(cx, buf);
        };
        let mut framed = buf.to_vec();
        let mut ahead = self.framing;
        ahead.frame(version, &mut framed);
        let written = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, &framed))?;
        self.framing.frame(version, &mut framed[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A flush with the ClientHello still incomplete sends its records as written.
        if !self.held.is_empty() {
            self.relaying = false;
            let held = std::mem::take(&mut self.held);
            self.pass(held);
        }
        std::task::ready!(self.poll_send(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
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
    Https(SslStream<HelloRecords<T>>),
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
            MaybeHttpsStream::Https(s) => &s.get_ref().io,
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

    fn socket(&self) -> Option<socket2::SockRef<'_>> {
        match self {
            MaybeHttpsStream::Http(s) => s.socket(),
            MaybeHttpsStream::Https(s) => s.get_ref().socket(),
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
