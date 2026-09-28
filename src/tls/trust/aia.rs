use std::{
    io,
    num::NonZeroUsize,
    ptr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use btls::{
    asn1::Asn1ObjectRef,
    error::ErrorStack,
    nid::Nid,
    stack::Stack,
    x509::{
        GeneralNameRef, X509, X509Ref, X509StoreContext, X509StoreContextRef, X509VerifyError,
        X509VerifyResult, store::X509StoreRef,
    },
};
use foreign_types::{ForeignType, ForeignTypeRef};
use lru::LruCache;

use crate::sync::Mutex;

/// How many missing issuers one verification fetches, one chain level each.
const MAX_LEVELS: usize = 3;

/// How many caIssuers URLs of one certificate are tried.
const MAX_URLS: usize = 3;

/// How long a URL that failed is not fetched again.
const FAILURE_TTL: Duration = Duration::from_secs(30);

/// The default fetcher's time limit for one URL, redirects included.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// The default fetcher's response body limit.
const MAX_BODY: u64 = 64 * 1024;

/// How many redirects the default fetcher follows.
const MAX_REDIRECTS: u32 = 3;

type Fetch = dyn Fn(&str) -> io::Result<Vec<u8>> + Send + Sync;

/// Issuer certificates fetched from the Authority Information Access (AIA) caIssuers URLs
/// of server certificates, cached for every client and connector sharing this cache.
///
/// With one, a certificate verification that fails because an issuer is missing, as when a
/// server leaves out its intermediates, fetches the issuer from the caIssuers URL of the
/// certificate lacking it, as browsers do, and verifies again with it as an untrusted
/// intermediate, for up to three chain levels. The chain must still end at a trusted root
/// and pass every other check; when it doesn't, the last verification's error stands.
///
/// The cache holds the certificates of its capacity of URLs, dropping the least recently
/// used, and remembers a URL that failed for 30 seconds, during which verifications
/// needing it fail without fetching.
///
/// A fetch runs inside the handshake and blocks it: on a multi-threaded tokio runtime
/// through [`tokio::task::block_in_place`], elsewhere blocking the thread (stalling a
/// current-thread runtime meanwhile). Cached URLs don't block.
#[derive(Clone)]
pub struct AiaCache(Arc<Inner>);

struct Inner {
    entries: Mutex<LruCache<Box<str>, Entry>>,
    fetch: Box<Fetch>,
}

enum Entry {
    Issuers(Vec<X509>),
    Failed { until: Instant },
}

impl AiaCache {
    /// A cache of up to `capacity` URLs' certificates, fetched with a plain HTTP GET: only
    /// `http://` URLs (an `https://` one would need a verification of its own), following up
    /// to three redirects to `http://` URLs, with 5 seconds and 64 KiB per URL, and no proxy.
    pub fn new(capacity: NonZeroUsize) -> AiaCache {
        AiaCache::with_fetcher(capacity, fetch)
    }

    /// A cache of up to `capacity` URLs' certificates, fetched with `fetch`, which returns
    /// the body a caIssuers URL serves: a DER certificate, DER PKCS#7 certificates (`.p7c`),
    /// or PEM certificates.
    pub fn with_fetcher<F>(capacity: NonZeroUsize, fetch: F) -> AiaCache
    where
        F: Fn(&str) -> io::Result<Vec<u8>> + Send + Sync + 'static,
    {
        AiaCache(Arc::new(Inner {
            entries: Mutex::new(LruCache::new(capacity)),
            fetch: Box::new(fetch),
        }))
    }

    /// Verifies the peer certificate of `ctx`, which BoringSSL set up, as BoringSSL does,
    /// then, while that fails for a missing issuer, again with the issuers fetched for the
    /// certificate lacking one. `ctx` keeps the last verification's result.
    pub(crate) fn verify(&self, ctx: &mut X509StoreContextRef) -> bool {
        if ctx.verify_cert().unwrap_or(false) {
            return true;
        }

        let (Some(leaf), Some(mut lacking)) = (
            ctx.cert().map(ToOwned::to_owned),
            ctx.current_cert().map(ToOwned::to_owned),
        ) else {
            return false;
        };
        let mut untrusted: Vec<X509> = ctx
            .untrusted()
            .into_iter()
            .flatten()
            .map(ToOwned::to_owned)
            .collect();
        let mut result = ctx.verify_result();

        for _ in 0..MAX_LEVELS {
            if !issuer_missing(result) {
                break;
            }
            let issuers = self.issuers(&lacking);
            if issuers.is_empty() {
                break;
            }
            untrusted.extend(issuers);

            let Ok((verified, retried, current)) = reverify(ctx, &leaf, &untrusted) else {
                break;
            };
            ctx.set_error(retried);
            if verified {
                return true;
            }
            // A certificate still lacking its issuer after its fetch has no other to try.
            match current {
                Some(cert) if cert.as_ptr() != lacking.as_ptr() => lacking = cert,
                _ => break,
            }
            result = retried;
        }
        false
    }

    /// The certificates the first of `cert`'s caIssuers URLs that serves any serves.
    fn issuers(&self, cert: &X509Ref) -> Vec<X509> {
        ca_issuers(cert)
            .iter()
            .take(MAX_URLS)
            .find_map(|url| self.get(url))
            .unwrap_or_default()
    }

    /// The certificates `url` serves, cached or fetched, or `None` when it failed.
    fn get(&self, url: &str) -> Option<Vec<X509>> {
        match self.0.entries.lock().get(url) {
            Some(Entry::Issuers(certs)) => return Some(certs.clone()),
            Some(Entry::Failed { until }) if *until > Instant::now() => return None,
            _ => {}
        }

        let (entry, certs) = match blocking(|| (self.0.fetch)(url)).and_then(|body| parse(&body)) {
            Ok(certs) => (Entry::Issuers(certs.clone()), Some(certs)),
            Err(_err) => {
                debug!("tls AIA fetch of {} failed: {}", url, _err);
                let until = Instant::now() + FAILURE_TTL;
                (Entry::Failed { until }, None)
            }
        };
        self.0.entries.lock().put(url.into(), entry);
        certs
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

/// Verifies `leaf` again as BoringSSL set `ctx` up to verify it (trust store, parameters,
/// verify callback and connection), with `untrusted` as the peer's chain. Returns whether it
/// verified, the result, and the certificate an error concerns.
#[allow(unsafe_code)]
fn reverify(
    ctx: &X509StoreContextRef,
    leaf: &X509Ref,
    untrusted: &[X509],
) -> Result<(bool, X509VerifyResult, Option<X509>), ErrorStack> {
    let mut chain = Stack::new()?;
    for cert in untrusted {
        chain.push(cert.clone())?;
    }

    let original = ctx.as_ptr();
    // SAFETY: BoringSSL initialized `ctx` with a live store for the verification running.
    let store = unsafe { X509StoreRef::from_ptr(btls_sys::X509_STORE_CTX_get0_store(original)) };
    X509StoreContext::new()?.init(store, leaf, &chain, |retry| {
        let ptr = retry.as_ptr();
        // SAFETY: both contexts are initialized; `retry` owns the parameters it is given
        // before copying into them, and the connection outlives the verification.
        unsafe {
            let param = btls_sys::X509_VERIFY_PARAM_new();
            if param.is_null() {
                return Err(ErrorStack::get());
            }
            btls_sys::X509_STORE_CTX_set0_param(ptr, param);
            let idx = btls_sys::SSL_get_ex_data_X509_STORE_CTX_idx();
            let ssl = btls_sys::X509_STORE_CTX_get_ex_data(original, idx);
            if btls_sys::X509_VERIFY_PARAM_set1(
                param,
                btls_sys::X509_STORE_CTX_get0_param(original),
            ) == 0
                || btls_sys::X509_STORE_CTX_set_ex_data(ptr, idx, ssl) == 0
            {
                return Err(ErrorStack::get());
            }
            if let Some(callback) = btls_sys::SSL_get_verify_callback(ssl.cast()) {
                btls_sys::X509_STORE_CTX_set_verify_cb(ptr, Some(callback));
            }
        }
        let verified = retry.verify_cert()?;
        Ok((
            verified,
            retry.verify_result(),
            retry.current_cert().map(ToOwned::to_owned),
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

/// Runs `f`, which blocks, without stalling the other tasks of a multi-threaded tokio
/// runtime it runs on.
fn blocking<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "tokio-rt")]
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|rt| rt.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        return tokio::task::block_in_place(f);
    }
    f()
}

/// The default fetcher: a plain HTTP GET of an `http://` URL.
fn fetch(url: &str) -> io::Result<Vec<u8>> {
    // Without a TLS provider, redirects to `https://` URLs fail too.
    static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(FETCH_TIMEOUT))
            .max_redirects(MAX_REDIRECTS)
            .proxy(None)
            .build()
            .into()
    });

    if !url
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only http:// URLs are fetched",
        ));
    }
    AGENT
        .get(url)
        .call()
        .and_then(|mut response| {
            response
                .body_mut()
                .with_config()
                .limit(MAX_BODY)
                .read_to_vec()
        })
        .map_err(io::Error::other)
}
