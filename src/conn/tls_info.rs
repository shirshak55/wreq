use std::sync::Arc;

use bytes::Bytes;
use tokio_btls::SslStream;

use crate::tls::{TlsConnectionUse, TlsInfo, conn::MaybeHttpsStream};

/// A trait for extracting TLS information from a connection.
pub trait TlsInfoFactory {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

fn extract_tls_info<S>(ssl_stream: &SslStream<S>) -> TlsInfo {
    tls_info_of(ssl_stream.ssl())
}

/// The TLS `ssl` negotiated so far.
pub(crate) fn tls_info_of(ssl: &btls::ssl::SslRef) -> TlsInfo {
    TlsInfo {
        version: ssl.version_str(),
        cipher: ssl
            .current_cipher()
            .map(|cipher| cipher.standard_name().unwrap_or_else(|| cipher.name())),
        alpn_protocol: ssl.selected_alpn_protocol().map(Bytes::copy_from_slice),
        connection: Arc::new(TlsConnectionUse::default()),
        client_hello: crate::tls::conn::client_hello_index()
            .ok()
            .and_then(|index| ssl.ex_data(index))
            .cloned(),
        server_flight: crate::tls::conn::server_flight_index()
            .ok()
            .and_then(|index| ssl.ex_data(index))
            .cloned(),
        group: ssl.curve(),
        hello_retry_request: ssl.used_hello_retry_request(),
        aia_fetches: crate::tls::trust::aia::fetches(ssl),
        verified_path: crate::tls::trust::aia::verified_path(ssl),
        peer_ocsp: ssl.ocsp_status().map(Bytes::copy_from_slice),
        dhe_bits: ssl.session().and_then(|session| session.dhe_bits()),
        verify_error: crate::tls::trust::aia::verify_result(ssl)
            .err()
            .map(|error| (error.as_raw(), error.error_string())),
        peer_certificate: ssl
            .peer_certificate()
            .and_then(|cert| cert.to_der().ok())
            .map(Bytes::from),
        peer_certificate_chain: ssl.peer_cert_chain().map(|chain| {
            chain
                .iter()
                .filter_map(|cert| cert.to_der().ok())
                .map(Bytes::from)
                .collect()
        }),
    }
}

// Generic impl: any SslStream can provide TLS info.
impl<T> TlsInfoFactory for SslStream<T> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

// Generic impl: MaybeHttpsStream delegates to the inner stream.
impl<T: TlsInfoFactory> TlsInfoFactory for MaybeHttpsStream<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}
