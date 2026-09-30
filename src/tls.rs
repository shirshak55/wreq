//!  TLS options configuration
//!
//! - Various parts of TLS can also be configured or even disabled on the `ClientBuilder`.

pub(super) mod conn;

pub mod compress;
pub mod keylog;
pub mod session;
pub mod trust;

use std::borrow::Cow;

/// Re-exports of TLS-related types from `btls` for public use.
pub use btls::ssl::{ExtensionType, KeyShare};
use bytes::{BufMut, Bytes, BytesMut};
use compress::CertificateCompressor;
pub use conn::{HandshakeFailure, QuicSsl, QuicTlsConnector, QuicTlsConnectorBuilder, TlsStream};

/// Http extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Bytes>,
    pub(crate) peer_certificate_chain: Option<Vec<Bytes>>,
    pub(crate) version: &'static str,
    pub(crate) cipher: Option<&'static str>,
    pub(crate) alpn_protocol: Option<Bytes>,
    pub(crate) connection: std::sync::Arc<TlsConnectionUse>,
    pub(crate) client_hello: Option<Bytes>,
    pub(crate) server_flight: Option<conn::SharedFlight>,
    pub(crate) group: Option<u16>,
    pub(crate) hello_retry_request: bool,
    pub(crate) aia_fetches: Vec<trust::AiaFetch>,
    pub(crate) peer_ocsp: Option<Bytes>,
}

/// The raw handshake messages an origin sent this connection (its server flight), in the
/// order received, captured by the connection's BoringSSL message callback (see
/// `crate::tls::conn`). Each entry is one handshake message: its one-byte type, its
/// three-byte length, and its body — without the record-layer header.
///
/// A downstream TLS server can parse these to reproduce the origin's handshake to the
/// real client: the ServerHello (its chosen version, cipher, group and extension order),
/// a HelloRetryRequest (a ServerHello whose random is the well-known HRR marker), the
/// EncryptedExtensions (ALPN, ALPS, and their order), the Certificate message, the
/// CertificateVerify (its signature algorithm), NewSessionTicket(s) (their count,
/// lifetime and ticket size), and for TLS 1.2 the ServerKeyExchange and
/// CertificateRequest.
///
/// Tickets arrive after the handshake completes, so the flight grows as the connection is
/// read; take a snapshot once the response head is in hand for the tickets sent so far.
#[derive(Debug, Clone, Default)]
pub struct ServerFlight {
    messages: Vec<Bytes>,
}

/// Lets a client connection's handshake wait, once the server's flight is in and its
/// certificate verified, for the application settings (ALPS) it sends: a proxy learning
/// them from its own client mid-handshake supplies them then (see
/// [`RequestBuilder::alps_gate`](crate::RequestBuilder::alps_gate)). The handshake pauses
/// only when the server negotiated ALPS; [`AlpsGate::paused`] resolves with what the
/// server sent so far when it does.
#[derive(Clone, Debug)]
pub struct AlpsGate {
    paused: tokio::sync::watch::Sender<Option<TlsInfo>>,
    settings: tokio::sync::watch::Sender<Option<Option<Vec<u8>>>>,
}

impl Default for AlpsGate {
    fn default() -> Self {
        Self::new()
    }
}

impl AlpsGate {
    /// A gate no handshake has paused on yet.
    pub fn new() -> Self {
        Self {
            paused: tokio::sync::watch::Sender::new(None),
            settings: tokio::sync::watch::Sender::new(None),
        }
    }

    /// Resolves once the handshake pauses, with the server's flight so far.
    pub async fn paused(&self) -> TlsInfo {
        let mut paused = self.paused.subscribe();
        loop {
            if let Some(info) = paused.borrow_and_update().clone() {
                return info;
            }
            if paused.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Supplies the settings the connection sends (none: the ones it was configured
    /// with), resuming its handshake.
    pub fn supply(&self, settings: Option<Vec<u8>>) {
        self.settings.send_replace(Some(settings));
    }

    pub(crate) fn pause(&self, info: TlsInfo) {
        self.paused.send_replace(Some(info));
    }

    pub(crate) async fn settings(&self) -> Option<Vec<u8>> {
        let mut settings = self.settings.subscribe();
        loop {
            if let Some(settings) = settings.borrow_and_update().clone() {
                return settings;
            }
            if settings.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// A TLS handshake message type this crate names for callers reading a [`ServerFlight`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandshakeType {
    /// A ServerHello (TLS 1.2 and 1.3).
    ServerHello,
    /// A ServerHello whose random is the RFC 8446 HelloRetryRequest marker.
    HelloRetryRequest,
    /// A TLS 1.3 EncryptedExtensions message.
    EncryptedExtensions,
    /// A Certificate message.
    Certificate,
    /// A CertificateVerify message.
    CertificateVerify,
    /// A TLS 1.2 ServerKeyExchange message.
    ServerKeyExchange,
    /// A CertificateRequest message (client authentication).
    CertificateRequest,
    /// A TLS 1.2 ServerHelloDone message.
    ServerHelloDone,
    /// A NewSessionTicket message.
    NewSessionTicket,
    /// A Finished message.
    Finished,
    /// Any other handshake type, by its wire code.
    Other(u8),
}

impl ServerFlight {
    /// The well-known SHA-256 marker a ServerHello carries as its random to signal a
    /// HelloRetryRequest (RFC 8446 section 4.1.3).
    const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];

    /// The raw handshake messages received so far, in order (type + 3-byte length + body).
    #[must_use]
    pub fn messages(&self) -> &[Bytes] {
        &self.messages
    }

    /// The classified messages received so far, in order: each type paired with its raw
    /// bytes (type + 3-byte length + body). A ServerHello carrying the HRR random is
    /// reported as [`HandshakeType::HelloRetryRequest`].
    #[must_use]
    pub fn classified(&self) -> Vec<(HandshakeType, &Bytes)> {
        self.messages
            .iter()
            .map(|msg| (Self::classify(msg), msg))
            .collect()
    }

    fn classify(msg: &Bytes) -> HandshakeType {
        match msg.first().copied() {
            Some(2) => {
                // ServerHello: type(1) len(3) legacy_version(2) random(32)...
                let random = msg.get(6..38);
                if random == Some(&Self::HRR_RANDOM[..]) {
                    HandshakeType::HelloRetryRequest
                } else {
                    HandshakeType::ServerHello
                }
            }
            Some(8) => HandshakeType::EncryptedExtensions,
            Some(11) => HandshakeType::Certificate,
            Some(15) => HandshakeType::CertificateVerify,
            Some(12) => HandshakeType::ServerKeyExchange,
            Some(13) => HandshakeType::CertificateRequest,
            Some(14) => HandshakeType::ServerHelloDone,
            Some(4) => HandshakeType::NewSessionTicket,
            Some(20) => HandshakeType::Finished,
            Some(other) => HandshakeType::Other(other),
            None => HandshakeType::Other(0),
        }
    }

    /// The number of NewSessionTicket messages received so far.
    #[must_use]
    pub fn ticket_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|msg| matches!(Self::classify(msg), HandshakeType::NewSessionTicket))
            .count()
    }
}

impl From<Vec<Bytes>> for ServerFlight {
    fn from(messages: Vec<Bytes>) -> Self {
        Self { messages }
    }
}

/// The connection a [`TlsInfo`] was taken from, shared by every response it carries.
#[derive(Debug, Default)]
pub(crate) struct TlsConnectionUse {
    id: std::sync::OnceLock<u64>,
    responses: std::sync::atomic::AtomicU64,
}

impl TlsInfo {
    /// The negotiated protocol version, e.g. `TLSv1.3`.
    pub fn version(&self) -> &str {
        self.version
    }

    /// The negotiated cipher suite, by its standard (RFC) name when it has one.
    pub fn cipher(&self) -> Option<&str> {
        self.cipher
    }

    /// The protocol selected through ALPN, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// The negotiated key exchange group's TLS id (e.g. 29 for X25519), if any.
    pub fn group(&self) -> Option<u16> {
        self.group
    }

    /// Whether the server answered the first ClientHello with a HelloRetryRequest.
    pub fn hello_retry_request(&self) -> bool {
        self.hello_retry_request
    }

    /// The caIssuers URLs whose issuers the certificate verification needed (see
    /// [`AiaCache`](trust::AiaCache)), in the order it needed them.
    pub fn aia_fetches(&self) -> &[trust::AiaFetch] {
        &self.aia_fetches
    }

    /// The ClientHello handshake message (type, length and body, without the record
    /// header) this connection sent first.
    pub fn client_hello(&self) -> Option<&[u8]> {
        self.client_hello.as_deref()
    }

    /// The origin's server flight: the raw handshake messages it sent this connection, in
    /// order, as captured so far — the NewSessionTickets arrive after the handshake, once
    /// the connection is read. See [`ServerFlight`].
    pub fn server_flight(&self) -> Option<ServerFlight> {
        self.server_flight
            .as_ref()
            .map(|messages| ServerFlight::from(messages.lock().clone()))
    }

    /// The DER OCSP response the origin stapled (its `CertificateStatus` / TLS 1.3
    /// status_request), if it stapled one and this connection requested stapling.
    pub fn peer_ocsp(&self) -> Option<&[u8]> {
        self.peer_ocsp.as_deref()
    }

    /// An id for the TLS connection this response arrived on, the same for every response
    /// it carries: `assign` provides it for the connection's first caller.
    pub fn connection_id(&self, assign: impl FnOnce() -> u64) -> u64 {
        *self.connection.id.get_or_init(assign)
    }

    /// Counts one response carried by this connection and returns how many it carried
    /// before, so the first response on a fresh connection reads `0`.
    pub fn count_response(&self) -> u64 {
        self.connection
            .responses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// Get the DER encoded certificate chain of the peer.
    ///
    /// This includes the leaf certificate on the client side.
    pub fn peer_certificate_chain(&self) -> Option<impl Iterator<Item = &[u8]>> {
        self.peer_certificate_chain
            .as_ref()
            .map(|v| v.iter().map(|b| b.as_ref()))
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TlsVersion(btls::ssl::SslVersion);

impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1);

    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_1);

    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_2);

    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_3);
}

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(Cow<'static, [u8]>);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(Cow::Borrowed(b"http/1.1"));

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(Cow::Borrowed(b"h2"));

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(Cow::Borrowed(b"h3"));

    /// A protocol by its identification sequence, such as any a client offered.
    #[inline]
    pub fn new(id: impl Into<Cow<'static, [u8]>>) -> AlpnProtocol {
        AlpnProtocol(id.into())
    }

    #[inline]
    fn encode(self) -> Bytes {
        Self::encode_sequence(std::iter::once(&self))
    }

    fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpnProtocol>,
    {
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(&item.0);
        }
        buf.freeze()
    }
}

impl PartialEq<[u8]> for AlpnProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        *self.0 == *other
    }
}

/// A TLS ALPS protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

impl AlpsProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpsProtocol = AlpsProtocol(b"h3");
}

impl PartialEq<[u8]> for AlpsProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// Builder for `[`TlsOptions`]`.
#[must_use]
#[derive(Debug, Clone)]
pub struct TlsOptionsBuilder {
    config: TlsOptions,
}

/// TLS connection configuration options.
///
/// This struct provides fine-grained control over the behavior of TLS
/// connections, including:
/// - **Protocol negotiation** (ALPN, ALPS, TLS versions)
/// - **Session management** (tickets, PSK, key shares)
/// - **Security & privacy** (OCSP, GREASE, ECH, delegated credentials)
/// - **Performance tuning** (record size, cipher preferences, hardware overrides)
///
/// All fields are optional or have defaults. See each field for details.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TlsOptions {
    /// Application-Layer Protocol Negotiation ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
    ///
    /// Specifies which application protocols (e.g., HTTP/2, HTTP/1.1) may be negotiated
    /// over a single TLS connection.
    ///
    /// **Default:** `Some([HTTP/2, HTTP/1.1])`
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// Application-Layer Protocol Settings (ALPS).
    ///
    /// Enables exchanging application-layer settings during the handshake
    /// for protocols negotiated via ALPN.
    ///
    /// **Default:** `None`
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Whether to use an alternative ALPS codepoint for compatibility.
    ///
    /// Useful when larger ALPS payloads are required.
    ///
    /// **Default:** `false`
    pub alps_use_new_codepoint: bool,

    /// Enables TLS Session Tickets ([RFC 5077](https://tools.ietf.org/html/rfc5077)).
    ///
    /// Allows session resumption without requiring server-side state.
    ///
    /// **Default:** `true`
    pub session_ticket: bool,

    /// Minimum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub max_tls_version: Option<TlsVersion>,

    /// Enables Pre-Shared Key (PSK) cipher suites ([RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279)).
    ///
    /// Authentication relies on out-of-band pre-shared keys instead of certificates.
    ///
    /// **Default:** `false`
    pub pre_shared_key: bool,

    /// Controls whether to send a GREASE Encrypted ClientHello (ECH) extension
    /// when no supported ECH configuration is available.
    ///
    /// GREASE prevents protocol ossification by sending unknown extensions.
    ///
    /// **Default:** `false`
    pub enable_ech_grease: bool,

    /// Controls whether ClientHello extensions should be permuted.
    ///
    /// **Default:** `None` (implementation default)
    pub permute_extensions: Option<bool>,

    /// Controls whether GREASE extensions ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701))
    /// are enabled in general.
    ///
    /// **Default:** `None` (implementation default)
    pub grease_enabled: Option<bool>,

    /// Enables OCSP stapling for the connection.
    ///
    /// **Default:** `false`
    pub enable_ocsp_stapling: bool,

    /// Enables Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`
    pub enable_signed_cert_timestamps: bool,

    /// Sets the maximum TLS record size.
    ///
    /// **Default:** `None`
    pub record_size_limit: Option<u16>,

    /// Whether to skip session tickets when using PSK.
    ///
    /// **Default:** `false`
    pub psk_skip_session_ticket: bool,

    /// Whether to set specific key shares for TLS 1.3 handshakes.
    ///
    /// **Default:** `None`
    pub key_shares: Option<Cow<'static, [KeyShare]>>,

    /// Enables PSK with (EC)DHE key establishment (`psk_dhe_ke`).
    ///
    /// **Default:** `true`
    pub psk_dhe_ke: bool,

    /// Enables TLS renegotiation by sending the `renegotiation_info` extension.
    ///
    /// **Default:** `true`
    pub renegotiation: bool,

    /// Delegated Credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// Allows TLS 1.3 endpoints to use temporary delegated credentials
    /// for authentication with reduced long-term key exposure.
    ///
    /// **Default:** `None`
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of supported elliptic curves.
    ///
    /// **Default:** `None`
    pub curves_list: Option<Cow<'static, str>>,

    /// List of supported signature algorithms.
    ///
    /// **Default:** `None`
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Cipher suite configuration string.
    ///
    /// Uses BoringSSL's mini-language to select, enable, and prioritize ciphers.
    ///
    /// **Default:** `None`
    pub cipher_list: Option<Cow<'static, str>>,

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// **Default:** `None`
    pub preserve_tls13_cipher_list: Option<bool>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`
    pub certificate_compressors: Option<Cow<'static, [&'static dyn CertificateCompressor]>>,

    /// Supported TLS extensions, used for extension ordering/permutation.
    ///
    /// **Default:** `None`
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Starts the `signature_algorithms` extension with a GREASE value
    /// ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// **Default:** `false`
    pub grease_signature_algorithms: bool,

    /// Whether [`Self::extension_permutation`] is the ClientHello's whole extension list: the
    /// listed extensions are sent in that order, each when its configuration calls for it, and
    /// no others. A GREASE value places a GREASE extension, [`ExtensionType::PADDING`] a padding
    /// extension of [`Self::padding_length`] bytes, [`ExtensionType::SIGNATURE_ALGORITHMS_CERT`]
    /// the [`Self::offered_sigalgs_cert`] list if set, and [`ExtensionType::ENCRYPT_THEN_MAC`] an
    /// encrypt_then_mac extension, which BoringSSL does not implement: a server accepting it for
    /// a CBC cipher suite is an offer-only selection (see [`Self::offered_cipher_suites`]).
    ///
    /// **Default:** `false`
    pub strict_extension_order: bool,

    /// The cipher suite list the initial ClientHello writes, verbatim and in order, each GREASE
    /// value standing for the connection's GREASE value. It may offer suites BoringSSL does not
    /// implement or [`Self::cipher_list`] does not enable: only the enabled ones it offers are
    /// negotiated, and a server selecting another fails the handshake as an offer-only
    /// selection (see [`HandshakeFailure::offer_only_selection`]). The `offered_*` lists below
    /// work alike.
    ///
    /// **Default:** `None`
    pub offered_cipher_suites: Option<Cow<'static, [u16]>>,

    /// The supported_groups list the initial ClientHello writes; [`Self::curves_list`] is
    /// what is negotiated.
    ///
    /// **Default:** `None`
    pub offered_groups: Option<Cow<'static, [u16]>>,

    /// The groups the initial ClientHello sends key shares for, in order, a GREASE value
    /// placing a GREASE key share: each an enabled group [`Self::offered_groups`] offers, at
    /// most once. Takes precedence over [`Self::key_shares`].
    ///
    /// **Default:** `None`
    pub offered_key_shares: Option<Cow<'static, [u16]>>,

    /// The supported_versions list the initial ClientHello writes, sent even when the
    /// maximum version is below TLS 1.3; [`Self::min_tls_version`] to
    /// [`Self::max_tls_version`] is what is negotiated.
    ///
    /// **Default:** `None`
    pub offered_versions: Option<Cow<'static, [u16]>>,

    /// The signature_algorithms list the initial ClientHello writes; [`Self::sigalgs_list`]
    /// is what is negotiated. A server certificate whose key type BoringSSL does not implement
    /// is also an offer-only selection when this offers algorithms `sigalgs_list` lacks.
    ///
    /// **Default:** `None`
    pub offered_sigalgs: Option<Cow<'static, [u16]>>,

    /// The signature_algorithms_cert list the initial ClientHello writes where a strict
    /// extension order places it (see [`Self::strict_extension_order`]).
    ///
    /// **Default:** `None`
    pub offered_sigalgs_cert: Option<Cow<'static, [u16]>>,

    /// The ec_point_formats list the initial ClientHello writes. BoringSSL takes only
    /// uncompressed points, so a server's compressed ECDHE point is an offer-only selection
    /// when this offers a compressed format.
    ///
    /// **Default:** `None`
    pub offered_point_formats: Option<Cow<'static, [u8]>>,

    /// The length of the padding extension a strict extension order places.
    ///
    /// **Default:** `0`
    pub padding_length: u16,

    /// Ends the cipher suite list with TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    /// ([RFC 5746](https://datatracker.ietf.org/doc/html/rfc5746)).
    ///
    /// **Default:** `false`
    pub renegotiation_scsv: bool,

    /// Trust anchor IDs to request, as the encoded list of the `trust_anchors` extension.
    ///
    /// **Default:** `None`
    pub trust_anchors: Option<Cow<'static, [u8]>>,

    /// The length of the random legacy session ID a ClientHello resuming no session by ID
    /// or TLS 1.2 ticket carries, at most 32 bytes; a TLS 1.3 one without also sends no
    /// compatibility mode ChangeCipherSpec. `None` sends 32 bytes when offering TLS 1.3,
    /// else none.
    ///
    /// **Default:** `None`
    pub session_id_length: Option<u8>,

    /// The record version of the handshake records carrying the ClientHello (those written
    /// before the server's first byte), rather than BoringSSL's TLS 1.0 (`0x0301`).
    ///
    /// **Default:** `None`
    pub hello_record_version: Option<u16>,

    /// The length of the random payload of the GREASE ECH extension (see
    /// [`TlsOptions::enable_ech_grease`]), at least 1 byte. `None` picks a random multiple of
    /// 32 bytes from 128 to 224 plus the 16-byte AEAD tag.
    ///
    /// **Default:** `None`
    pub ech_grease_payload_length: Option<u16>,

    /// The HPKE `(kdf_id, aead_id)` cipher suite the GREASE ECH extension names, as given.
    /// `None` names HKDF-SHA256 with AES-128-GCM with AES hardware, else ChaCha20-Poly1305.
    ///
    /// **Default:** `None`
    pub ech_grease_cipher_suite: Option<(u16, u16)>,

    /// Overrides AES hardware acceleration.
    ///
    /// **Default:** `None`
    pub aes_hw_override: Option<bool>,

    /// Overrides the random AES hardware acceleration.
    ///
    /// **Default:** `false`
    pub random_aes_hw_override: bool,
}

impl TlsOptionsBuilder {
    /// Sets the ALPN protocols to use.
    #[inline]
    pub fn alpn_protocols<I>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = AlpnProtocol>,
    {
        self.config.alpn_protocols = Some(Cow::Owned(alpn.into_iter().collect()));
        self
    }

    /// Sets the ALPS protocols to use.
    #[inline]
    pub fn alps_protocols<I>(mut self, alps: I) -> Self
    where
        I: IntoIterator<Item = AlpsProtocol>,
    {
        self.config.alps_protocols = Some(Cow::Owned(alps.into_iter().collect()));
        self
    }

    /// Sets whether to use a new codepoint for ALPS.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }
    /// Sets the session ticket flag.
    #[inline]
    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.config.session_ticket = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_tls_version = version.into();
        self
    }

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets the GREASE ECH extension flag.
    #[inline]
    pub fn enable_ech_grease(mut self, enabled: bool) -> Self {
        self.config.enable_ech_grease = enabled;
        self
    }

    /// Sets whether to permute ClientHello extensions.
    #[inline]
    pub fn permute_extensions<T>(mut self, permute: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the GREASE enabled flag.
    #[inline]
    pub fn grease_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets the OCSP stapling flag.
    #[inline]
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    #[inline]
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    #[inline]
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the PSK skip session ticket flag.
    #[inline]
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = enabled;
        self
    }

    /// Sets the renegotiation flag.
    #[inline]
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = enabled;
        self
    }

    /// Sets the delegated credentials.
    #[inline]
    pub fn delegated_credentials<T>(mut self, creds: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the client key shares to be used in the TLS 1.3 handshake.
    #[inline]
    pub fn key_shares<T>(mut self, key_shares: T) -> Self
    where
        T: Into<Cow<'static, [KeyShare]>>,
    {
        self.config.key_shares = Some(key_shares.into());
        self
    }

    /// Sets the supported curves list.
    #[inline]
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the cipher list.
    #[inline]
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the supported signature algorithms.
    #[inline]
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compressors<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [&'static dyn CertificateCompressor]>>,
    {
        self.config.certificate_compressors = Some(algs.into());
        self
    }

    /// Sets the extension permutation.
    #[inline]
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Sets whether to start the `signature_algorithms` extension with a GREASE value.
    #[inline]
    pub fn grease_signature_algorithms(mut self, enabled: bool) -> Self {
        self.config.grease_signature_algorithms = enabled;
        self
    }

    /// Sets whether the extension permutation is the ClientHello's whole extension list.
    #[inline]
    pub fn strict_extension_order(mut self, enabled: bool) -> Self {
        self.config.strict_extension_order = enabled;
        self
    }

    /// Sets the cipher suite list the initial ClientHello writes.
    #[inline]
    pub fn offered_cipher_suites<T>(mut self, suites: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_cipher_suites = Some(suites.into());
        self
    }

    /// Sets the supported_groups list the initial ClientHello writes.
    #[inline]
    pub fn offered_groups<T>(mut self, groups: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_groups = Some(groups.into());
        self
    }

    /// Sets the groups the initial ClientHello sends key shares for.
    #[inline]
    pub fn offered_key_shares<T>(mut self, groups: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_key_shares = Some(groups.into());
        self
    }

    /// Sets the supported_versions list the initial ClientHello writes.
    #[inline]
    pub fn offered_versions<T>(mut self, versions: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_versions = Some(versions.into());
        self
    }

    /// Sets the signature_algorithms list the initial ClientHello writes.
    #[inline]
    pub fn offered_sigalgs<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_sigalgs = Some(sigalgs.into());
        self
    }

    /// Sets the signature_algorithms_cert list the initial ClientHello writes.
    #[inline]
    pub fn offered_sigalgs_cert<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, [u16]>>,
    {
        self.config.offered_sigalgs_cert = Some(sigalgs.into());
        self
    }

    /// Sets the ec_point_formats list the initial ClientHello writes.
    #[inline]
    pub fn offered_point_formats<T>(mut self, formats: T) -> Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.config.offered_point_formats = Some(formats.into());
        self
    }

    /// Sets the length of the padding extension a strict extension order places.
    #[inline]
    pub fn padding_length(mut self, len: u16) -> Self {
        self.config.padding_length = len;
        self
    }

    /// Sets whether to end the cipher suite list with TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
    #[inline]
    pub fn renegotiation_scsv(mut self, enabled: bool) -> Self {
        self.config.renegotiation_scsv = enabled;
        self
    }

    /// Sets the trust anchor IDs to request.
    #[inline]
    pub fn trust_anchors<T>(mut self, ids: T) -> Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.config.trust_anchors = Some(ids.into());
        self
    }

    /// Sets the length of the legacy session ID a ClientHello resuming no session carries.
    #[inline]
    pub fn session_id_length<T>(mut self, len: T) -> Self
    where
        T: Into<Option<u8>>,
    {
        self.config.session_id_length = len.into();
        self
    }

    /// Sets the record version of the records carrying the ClientHello.
    #[inline]
    pub fn hello_record_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<u16>>,
    {
        self.config.hello_record_version = version.into();
        self
    }

    /// Sets the length of the GREASE ECH extension's random payload.
    #[inline]
    pub fn ech_grease_payload_length<T>(mut self, len: T) -> Self
    where
        T: Into<Option<u16>>,
    {
        self.config.ech_grease_payload_length = len.into();
        self
    }

    /// Sets the HPKE `(kdf_id, aead_id)` cipher suite the GREASE ECH extension names.
    #[inline]
    pub fn ech_grease_cipher_suite<T>(mut self, suite: T) -> Self
    where
        T: Into<Option<(u16, u16)>>,
    {
        self.config.ech_grease_cipher_suite = suite.into();
        self
    }

    /// Sets the AES hardware override flag.
    #[inline]
    pub fn aes_hw_override<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.aes_hw_override = enabled.into();
        self
    }

    /// Sets the random AES hardware override flag.
    #[inline]
    pub fn random_aes_hw_override(mut self, enabled: bool) -> Self {
        self.config.random_aes_hw_override = enabled;
        self
    }

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// By default, BoringSSL does not preserve the TLS 1.3 cipher list. When this option is
    /// disabled (the default), BoringSSL uses its internal default TLS 1.3 cipher suites in its
    /// default order, regardless of what is set via [`Self::cipher_list`].
    ///
    /// When enabled, this option ensures that the TLS 1.3 cipher suites explicitly set via
    /// [`Self::cipher_list`] are retained in their original order, without being reordered or
    /// modified by BoringSSL's internal logic. This is useful for maintaining specific cipher suite
    /// priorities for TLS 1.3. Note that if [`Self::cipher_list`] does not include any TLS 1.3
    /// cipher suites, BoringSSL will still fall back to its default TLS 1.3 cipher suites and
    /// order.
    #[inline]
    pub fn preserve_tls13_cipher_list<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.preserve_tls13_cipher_list = enabled.into();
        self
    }

    /// Builds the `TlsOptions` from the builder.
    #[inline]
    pub fn build(self) -> TlsOptions {
        self.config
    }
}

impl TlsOptions {
    /// Creates a new `TlsOptionsBuilder` instance.
    pub fn builder() -> TlsOptionsBuilder {
        TlsOptionsBuilder {
            config: TlsOptions::default(),
        }
    }
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions {
            alpn_protocols: Some(Cow::Borrowed(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])),
            alps_protocols: None,
            alps_use_new_codepoint: false,
            session_ticket: true,
            min_tls_version: None,
            max_tls_version: None,
            pre_shared_key: false,
            enable_ech_grease: false,
            permute_extensions: None,
            grease_enabled: None,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            record_size_limit: None,
            psk_skip_session_ticket: false,
            key_shares: None,
            psk_dhe_ke: true,
            renegotiation: true,
            delegated_credentials: None,
            curves_list: None,
            cipher_list: None,
            sigalgs_list: None,
            certificate_compressors: None,
            extension_permutation: None,
            grease_signature_algorithms: false,
            strict_extension_order: false,
            offered_cipher_suites: None,
            offered_groups: None,
            offered_key_shares: None,
            offered_versions: None,
            offered_sigalgs: None,
            offered_sigalgs_cert: None,
            offered_point_formats: None,
            padding_length: 0,
            renegotiation_scsv: false,
            trust_anchors: None,
            session_id_length: None,
            hello_record_version: None,
            ech_grease_payload_length: None,
            ech_grease_cipher_suite: None,
            aes_hw_override: None,
            preserve_tls13_cipher_list: None,
            random_aes_hw_override: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocol_encode() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP2]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[
            AlpnProtocol::HTTP1,
            AlpnProtocol::HTTP2,
            AlpnProtocol::HTTP3,
        ]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2\x02h3"));
    }

    #[test]
    fn alpn_protocol_encode_single() {
        let alpn = AlpnProtocol::HTTP1.encode();
        assert_eq!(alpn, b"\x08http/1.1".as_ref());

        let alpn = AlpnProtocol::HTTP2.encode();
        assert_eq!(alpn, b"\x02h2".as_ref());

        let alpn = AlpnProtocol::HTTP3.encode();
        assert_eq!(alpn, b"\x02h3".as_ref());
    }
}
