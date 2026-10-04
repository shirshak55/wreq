use std::{
    future::Future,
    io,
    num::NonZeroUsize,
    os::raw::c_int,
    pin::Pin,
    ptr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use btls::{
    asn1::Asn1ObjectRef,
    error::ErrorStack,
    ex_data::Index,
    nid::Nid,
    ssl::{Ssl, SslAlert, SslRef, SslVerifyError},
    stack::Stack,
    x509::{GeneralNameRef, X509, X509Ref, X509StoreContext, X509VerifyError, X509VerifyResult},
};
use bytes::Bytes;
use foreign_types::{ForeignType, ForeignTypeRef};
use futures_util::future::{FutureExt, Shared};
use lru::LruCache;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_btls::SslStream;

use crate::sync::Mutex;
use crate::tls::AlpsGate;

/// How many missing issuers one verification fetches, one chain level each.
const MAX_LEVELS: usize = 3;

/// How many caIssuers URLs of one certificate are tried.
const MAX_URLS: usize = 3;

/// How long a URL that failed is not fetched again.
const FAILURE_TTL: Duration = Duration::from_secs(30);

/// The largest caIssuers response taken.
const MAX_BODY: usize = 64 * 1024;

type FetchFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;

type Fetch = dyn Fn(String) -> FetchFuture + Send + Sync;

/// A fetch of one URL, shared by every handshake waiting for it.
type Fetching = Shared<Pin<Box<dyn Future<Output = Fetched> + Send>>>;

/// The certificates a URL served, or why it served none.
type Fetched = Result<Vec<X509>, Arc<str>>;

/// Issuer certificates fetched from the Authority Information Access (AIA) caIssuers URLs
/// of server certificates, cached for every client and connector sharing this cache.
///
/// With one, a certificate verification that fails because an issuer is missing, as when a
/// server leaves out its intermediates, fetches the issuer from the caIssuers URL of the
/// certificate lacking it, as browsers do, and verifies again with it as an untrusted
/// intermediate, for up to three chain levels. The chain must still end at a trusted root
/// and pass every other check; when it doesn't, the last verification's error stands.
///
/// A fetch doesn't block: the handshake waits for it asynchronously, and handshakes needing
/// a URL already being fetched wait for that fetch. The fetcher bounds its own time; a
/// response over 64 KiB fails. The cache holds the certificates of its capacity of URLs,
/// dropping the least recently used, and remembers a URL that failed for 30 seconds, during
/// which verifications needing it fail without fetching.
#[derive(Clone)]
pub struct AiaCache(Arc<Inner>);

struct Inner {
    entries: Mutex<LruCache<Box<str>, Entry>>,
    fetch: Box<Fetch>,
}

enum Entry {
    Issuers(Vec<X509>),
    Failed { until: Instant, error: Arc<str> },
    Fetching(Fetching),
}

/// A caIssuers URL a connection's certificate verification needed (see
/// [`TlsInfo::aia_fetches`](crate::tls::TlsInfo::aia_fetches)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiaFetch {
    url: String,
    cached: bool,
    result: Result<usize, String>,
}

impl AiaFetch {
    /// The caIssuers URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the cache already held its outcome, so this connection didn't wait for it.
    pub fn cached(&self) -> bool {
        self.cached
    }

    /// How many certificates it served, unless it failed.
    pub fn certificates(&self) -> Option<usize> {
        self.result.as_ref().ok().copied()
    }

    /// Why it served none, if it failed.
    pub fn error(&self) -> Option<&str> {
        self.result.as_ref().err().map(String::as_str)
    }
}

/// A connection's verification state across the retries of its certificate verification.
#[derive(Default)]
struct State {
    /// The URLs it needed, with their outcomes.
    fetches: Vec<AiaFetch>,
    /// The URLs whose fetch it waited for.
    waited: Vec<String>,
    /// The fetch it waits for.
    pending: Option<Fetching>,
    /// Why its last verification failed.
    error: Option<X509VerifyError>,
    /// The certification path its last verification built, leaf first (DER).
    path: Vec<Bytes>,
    /// Whether the handshake paused for its ALPS gate, and the settings the gate
    /// supplied, to send once the verification is retried.
    alps_paused: bool,
    alps_settings: Option<Option<Vec<u8>>>,
}

fn gate_index() -> Result<Index<Ssl, AlpsGate>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, AlpsGate>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Makes `ssl`'s handshake wait on `gate` for its application settings (see
/// [`AlpsGate`]).
pub(crate) fn set_alps_gate(ssl: &mut Ssl, gate: AlpsGate) -> Result<(), ErrorStack> {
    ssl.set_ex_data(gate_index()?, gate);
    Ok(())
}

fn alps_gate(ssl: &SslRef) -> Option<&AlpsGate> {
    gate_index().ok().and_then(|index| ssl.ex_data(index))
}

fn state_index() -> Result<Index<Ssl, Mutex<State>>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Mutex<State>>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// What a lookup of a certificate's caIssuers URLs found.
enum Lookup {
    Issuers(Vec<X509>),
    Pending(Fetching),
    None,
}

impl AiaCache {
    /// A cache of up to `capacity` URLs' certificates, fetched with `fetch`, which resolves
    /// to the body a caIssuers URL serves: a DER certificate, DER PKCS#7 certificates
    /// (`.p7c`), or PEM certificates.
    pub fn new<F, Fut>(capacity: NonZeroUsize, fetch: F) -> AiaCache
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Vec<u8>>> + Send + 'static,
    {
        AiaCache(Arc::new(Inner {
            entries: Mutex::new(LruCache::new(capacity)),
            fetch: Box::new(move |url| Box::pin(fetch(url))),
        }))
    }

    /// The custom verification of a connection's peer certificate: BoringSSL's own, then,
    /// while that fails for a missing issuer, again with the issuers fetched for the
    /// certificate lacking one. A fetch still running pauses the handshake (see
    /// [`handshake`]).
    pub(crate) fn verify(&self, ssl: &mut SslRef) -> Result<(), SslVerifyError> {
        let index = state_index().map_err(|_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;
        if ssl.ex_data(index).is_none() {
            ssl.set_ex_data(index, Mutex::new(State::default()));
        }
        // The settings the ALPS gate supplied while the verification waited (see
        // [`handshake`]) go on the connection before this retry finishes it.
        let supplied = ssl
            .ex_data(index)
            .and_then(|state| state.lock().alps_settings.take());
        if let Some(Some(settings)) = supplied {
            // Failing here means the server negotiated no ALPS after all.
            let _ = ssl.set_pending_application_settings(&settings);
        }
        let ssl: &SslRef = ssl;
        let Some(state) = ssl.ex_data(index) else {
            return Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR));
        };
        let mut state = state.lock();
        state.pending = None;

        let internal = |_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR);
        let mut untrusted = Vec::new();
        let (mut verified, mut result, mut current, mut path) =
            verify_chain(ssl, &untrusted).map_err(internal)?;
        for _ in 0..MAX_LEVELS {
            if verified || !issuer_missing(result) {
                break;
            }
            let Some(lacking) = current.take() else {
                break;
            };
            match self.issuers(&lacking, &mut state) {
                Lookup::Issuers(issuers) => untrusted.extend(issuers),
                Lookup::Pending(fetch) => {
                    state.pending = Some(fetch);
                    return Err(SslVerifyError::Retry);
                }
                Lookup::None => break,
            }
            (verified, result, current, path) = verify_chain(ssl, &untrusted).map_err(internal)?;
            // A certificate still lacking its issuer after its fetch has no other to try.
            if current
                .as_ref()
                .is_some_and(|cert| cert.as_ptr() == lacking.as_ptr())
            {
                break;
            }
        }

        state.path = path;
        match result {
            // The verify callback may accept a chain despite an error.
            _ if verified => {
                state.error = None;
                if let Some(gate) = alps_gate(ssl)
                    && !state.alps_paused
                    && ssl.peer_application_settings().is_some()
                {
                    state.alps_paused = true;
                    // Reading the connection's TLS takes this state's lock again.
                    drop(state);
                    gate.pause(crate::conn::tls_info_of(ssl));
                    return Err(SslVerifyError::Retry);
                }
                Ok(())
            }
            result => {
                let error = result.err();
                state.error = error;
                let raw = error.map_or(btls_sys::X509_V_ERR_UNSPECIFIED as c_int, |error| {
                    error.as_raw()
                });
                // SAFETY: a pure mapping of a verification result to an alert.
                #[allow(unsafe_code)]
                let alert = unsafe { btls_sys::SSL_alert_from_verify_result(raw.into()) };
                Err(SslVerifyError::Invalid(alert_of(alert)))
            }
        }
    }

    /// The issuers the first of `cert`'s caIssuers URLs that serves any serves, or the
    /// fetch to wait for before the next URL is tried.
    fn issuers(&self, cert: &X509Ref, state: &mut State) -> Lookup {
        for url in ca_issuers(cert).into_iter().take(MAX_URLS) {
            match self.lookup(&url, state) {
                Some(Ok(issuers)) => return Lookup::Issuers(issuers),
                Some(Err(fetch)) => return Lookup::Pending(fetch),
                None => {}
            }
        }
        Lookup::None
    }

    /// The certificates `url` serves: `Some(Ok)` when known, `None` when it failed, and
    /// `Some(Err)` with the fetch to wait for while one runs, started here if none is.
    fn lookup(&self, url: &str, state: &mut State) -> Option<Result<Vec<X509>, Fetching>> {
        // A URL that failed this connection isn't tried again for it.
        if state
            .fetches
            .iter()
            .any(|fetch| fetch.url == url && fetch.result.is_err())
        {
            return None;
        }

        let mut entries = self.0.entries.lock();
        let (fetched, finished) = match entries.get(url) {
            Some(Entry::Issuers(issuers)) => (Ok(issuers.clone()), false),
            Some(Entry::Failed { until, error }) if *until > Instant::now() => {
                (Err(Arc::clone(error)), false)
            }
            Some(Entry::Fetching(fetch)) => match fetch.peek() {
                Some(fetched) => (fetched.clone(), true),
                None => {
                    state.waited.push(url.to_owned());
                    return Some(Err(fetch.clone()));
                }
            },
            _ => {
                let fetch = (self.0.fetch)(url.to_owned());
                let fetch: Fetching = async move {
                    match fetch.await {
                        Ok(body) if body.len() > MAX_BODY => {
                            Err(format!("response over {MAX_BODY} bytes").into())
                        }
                        Ok(body) => parse(&body).map_err(|err| err.to_string().into()),
                        Err(err) => Err(err.to_string().into()),
                    }
                }
                .boxed()
                .shared();
                entries.put(url.into(), Entry::Fetching(fetch.clone()));
                state.waited.push(url.to_owned());
                return Some(Err(fetch));
            }
        };

        if finished {
            let entry = match &fetched {
                Ok(issuers) => Entry::Issuers(issuers.clone()),
                Err(error) => {
                    debug!("tls AIA fetch of {} failed: {}", url, error);
                    Entry::Failed {
                        until: Instant::now() + FAILURE_TTL,
                        error: Arc::clone(error),
                    }
                }
            };
            entries.put(url.into(), entry);
        }
        drop(entries);

        let cached = !state.waited.iter().any(|waited| waited == url);
        state.fetches.retain(|fetch| fetch.url != url);
        state.fetches.push(AiaFetch {
            url: url.to_owned(),
            cached,
            result: fetched
                .as_ref()
                .map(Vec::len)
                .map_err(|error| error.to_string()),
        });
        fetched.ok().map(Ok)
    }
}

/// Runs `stream`'s client handshake, waiting out the issuer fetches its certificate
/// verification pauses it for (see [`AiaCache`]).
pub(crate) async fn handshake<S>(stream: &mut SslStream<S>) -> Result<(), btls::ssl::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match Pin::new(&mut *stream).connect().await {
            Err(error) if error.code() == btls::ssl::ErrorCode::WANT_CERTIFICATE_VERIFY => {
                let state = state_index()
                    .ok()
                    .and_then(|index| stream.ssl().ex_data(index));
                let pending = state.and_then(|state| state.lock().pending.take());
                match pending {
                    Some(fetch) => {
                        let _ = fetch.await;
                    }
                    None => {
                        let gate = alps_gate(stream.ssl());
                        let waiting = state.is_some_and(|state| {
                            let state = state.lock();
                            state.alps_paused && state.alps_settings.is_none()
                        });
                        match (state, gate) {
                            (Some(state), Some(gate)) if waiting => {
                                let settings = gate.settings().await;
                                state.lock().alps_settings = Some(settings);
                            }
                            _ => return Err(error),
                        }
                    }
                }
            }
            result => return result,
        }
    }
}

/// The caIssuers URLs a connection's certificate verification needed.
pub(crate) fn fetches(ssl: &SslRef) -> Vec<AiaFetch> {
    state_index()
        .ok()
        .and_then(|index| ssl.ex_data(index))
        .map(|state| state.lock().fetches.clone())
        .unwrap_or_default()
}

/// The certification path a connection's certificate verification built, leaf first (DER):
/// to the trust anchor it reached, else as far as it got; `None` when none ran (a resumed
/// session).
pub(crate) fn verified_path(ssl: &SslRef) -> Option<Vec<Bytes>> {
    state_index()
        .ok()
        .and_then(|index| ssl.ex_data(index))
        .map(|state| state.lock().path.clone())
        .filter(|path| !path.is_empty())
}

/// Why a connection's certificate verification failed: BoringSSL reports a failed custom
/// verification as `X509_V_ERR_APPLICATION_VERIFICATION`, so the error this cache's verification
/// failed with, when it ran.
pub(crate) fn verify_result(ssl: &SslRef) -> X509VerifyResult {
    let error = state_index()
        .ok()
        .and_then(|index| ssl.ex_data(index))
        .and_then(|state| state.lock().error);
    match error {
        Some(error) => Err(error),
        None => ssl.verify_result(),
    }
}

/// Whether a verification failed because an issuer is in neither the peer's chain nor the
/// trust store.
fn issuer_missing(result: X509VerifyResult) -> bool {
    result.is_err_and(|err| {
        err == X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            || err == X509VerifyError::UNABLE_TO_GET_ISSUER_CERT
    })
}

/// The alert BoringSSL sends for a verification error it maps to `raw`.
fn alert_of(raw: c_int) -> SslAlert {
    [
        (btls_sys::SSL_AD_BAD_CERTIFICATE, SslAlert::BAD_CERTIFICATE),
        (
            btls_sys::SSL_AD_CERTIFICATE_EXPIRED,
            SslAlert::CERTIFICATE_EXPIRED,
        ),
        (
            btls_sys::SSL_AD_CERTIFICATE_REVOKED,
            SslAlert::CERTIFICATE_REVOKED,
        ),
        (
            btls_sys::SSL_AD_CERTIFICATE_UNKNOWN,
            SslAlert::CERTIFICATE_UNKNOWN,
        ),
        (btls_sys::SSL_AD_DECRYPT_ERROR, SslAlert::DECRYPT_ERROR),
        (
            btls_sys::SSL_AD_HANDSHAKE_FAILURE,
            SslAlert::HANDSHAKE_FAILURE,
        ),
        (btls_sys::SSL_AD_UNKNOWN_CA, SslAlert::UNKNOWN_CA),
        (
            btls_sys::SSL_AD_UNSUPPORTED_CERTIFICATE,
            SslAlert::UNSUPPORTED_CERTIFICATE,
        ),
    ]
    .into_iter()
    .find_map(|(code, alert)| (code as c_int == raw).then_some(alert))
    .unwrap_or(SslAlert::INTERNAL_ERROR)
}

/// Verifies the peer certificate chain of `ssl` exactly as BoringSSL does for a client
/// (`ssl_crypto_x509_session_verify_cert_chain`) — its context's trust store, the
/// connection's verify parameters, ECH name override and verify callback — with
/// `untrusted` added to the chain the peer sent. Returns whether it verified, the result,
/// the certificate an error concerns, and the certification path built (DER, leaf first).
#[allow(unsafe_code)]
fn verify_chain(
    ssl: &SslRef,
    untrusted: &[X509],
) -> Result<(bool, X509VerifyResult, Option<X509>, Vec<Bytes>), ErrorStack> {
    let peer = ssl.peer_cert_chain();
    let Some(leaf) = peer.and_then(|chain| chain.iter().next()) else {
        // SAFETY: the code of an existing verification error.
        let error = unsafe { X509VerifyError::from_raw(btls_sys::X509_V_ERR_UNSPECIFIED as c_int) };
        return Ok((false, error, None, Vec::new()));
    };
    let mut chain = Stack::new()?;
    for cert in peer
        .into_iter()
        .flatten()
        .chain(untrusted.iter().map(|cert| &**cert))
    {
        chain.push(cert.to_owned())?;
    }

    X509StoreContext::new()?.init(ssl.ssl_context().cert_store(), leaf, &chain, |ctx| {
        let ctx_ptr = ctx.as_ptr();
        let ssl_ptr = ssl.as_ptr();
        // SAFETY: `ctx` is initialized and `ssl` outlives the verification.
        unsafe {
            let mut name = ptr::null();
            let mut name_len = 0;
            btls_sys::SSL_get0_ech_name_override(ssl_ptr, &mut name, &mut name_len);
            let param = btls_sys::X509_STORE_CTX_get0_param(ctx_ptr);
            if btls_sys::X509_STORE_CTX_set_ex_data(
                ctx_ptr,
                btls_sys::SSL_get_ex_data_X509_STORE_CTX_idx(),
                ssl_ptr.cast(),
            ) == 0
                || btls_sys::X509_STORE_CTX_set_default(ctx_ptr, c"ssl_server".as_ptr()) == 0
                || btls_sys::X509_VERIFY_PARAM_set1(param, btls_sys::SSL_get0_param(ssl_ptr)) == 0
                || (name_len != 0
                    && btls_sys::X509_VERIFY_PARAM_set1_host(param, name, name_len) == 0)
            {
                return Err(ErrorStack::get());
            }
            if let Some(callback) = btls_sys::SSL_get_verify_callback(ssl_ptr) {
                btls_sys::X509_STORE_CTX_set_verify_cb(ctx_ptr, Some(callback));
            }
        }
        let verified = ctx.verify_cert()?;
        let path = ctx
            .chain()
            .into_iter()
            .flatten()
            .map(|cert| cert.to_der().map(Bytes::from))
            .collect::<Result<_, _>>()?;
        Ok((
            verified,
            ctx.verify_result(),
            ctx.current_cert().map(ToOwned::to_owned),
            path,
        ))
    })
}

/// The caIssuers URLs in `cert`'s Authority Information Access extension.
#[allow(unsafe_code)]
fn ca_issuers(cert: &X509Ref) -> Vec<String> {
    // SAFETY: the extension decodes into a stack of access descriptions this function owns
    // and frees; the URLs are copied out before.
    unsafe {
        let aia = btls_sys::X509_get_ext_d2i(
            cert.as_ptr(),
            btls_sys::NID_info_access,
            ptr::null_mut(),
            ptr::null_mut(),
        )
        .cast::<btls_sys::AUTHORITY_INFO_ACCESS>();
        if aia.is_null() {
            // Clear the error a malformed extension leaves.
            let _ = ErrorStack::get();
            return Vec::new();
        }
        let stack = aia.cast::<btls_sys::OPENSSL_STACK>();
        let urls = (0..btls_sys::OPENSSL_sk_num(stack))
            .map(|i| &*btls_sys::OPENSSL_sk_value(stack, i).cast::<btls_sys::ACCESS_DESCRIPTION>())
            .filter(|desc| Asn1ObjectRef::from_ptr(desc.method).nid() == Nid::AD_CA_ISSUERS)
            .filter_map(|desc| GeneralNameRef::from_ptr(desc.location).uri())
            .map(str::to_owned)
            .collect();
        btls_sys::AUTHORITY_INFO_ACCESS_free(aia);
        urls
    }
}

/// The certificates in a caIssuers response: a DER certificate, DER PKCS#7 certificates, or
/// PEM certificates.
fn parse(body: &[u8]) -> io::Result<Vec<X509>> {
    let certs = if body.first() == Some(&0x30) {
        X509::from_der(body)
            .map(|cert| vec![cert])
            .or_else(|_| pkcs7_certificates(body))
    } else {
        X509::stack_from_pem(body)
    }
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificate in the response",
        ));
    }
    Ok(certs)
}

/// The certificates of DER PKCS#7 SignedData.
#[allow(unsafe_code)]
fn pkcs7_certificates(der: &[u8]) -> Result<Vec<X509>, ErrorStack> {
    let certs = Stack::<X509>::new()?;
    let mut cbs = btls_sys::CBS {
        data: der.as_ptr(),
        len: der.len(),
    };
    // SAFETY: `certs` is a live stack and `cbs` spans `der`.
    if unsafe { btls_sys::PKCS7_get_certificates(certs.as_ptr(), &mut cbs) } == 0 {
        return Err(ErrorStack::get());
    }
    Ok(certs.into_iter().collect())
}
