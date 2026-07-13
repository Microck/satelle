use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use rustls_platform_verifier::BuilderVerifierExt;
use std::sync::Arc;

/// Direct HTTP and WSS clients share one trust policy: when a Host-specific
/// CA bundle is configured it replaces platform roots instead of extending
/// them. This keeps an unrelated public or enterprise CA from authenticating
/// the endpoint and receiving the bearer token.
pub(crate) fn configure_reqwest_trust(
    builder: reqwest::blocking::ClientBuilder,
    ca_bundle: Option<&[u8]>,
) -> Result<reqwest::blocking::ClientBuilder, ReqwestTrustError> {
    let Some(ca_bundle) = ca_bundle else {
        return Ok(builder);
    };
    let certificates = reqwest::Certificate::from_pem_bundle(ca_bundle)
        .map_err(ReqwestTrustError::InvalidCaBundle)?;
    if certificates.is_empty() {
        return Err(ReqwestTrustError::EmptyCaBundle);
    }
    Ok(builder.tls_certs_only(certificates))
}

pub(crate) fn websocket_tls_config(
    ca_bundle: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, WebSocketTrustError> {
    let builder = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ]);
    let config = if let Some(ca_bundle) = ca_bundle {
        let mut roots = RootCertStore::empty();
        let mut certificate_count = 0;
        for certificate in CertificateDer::pem_slice_iter(ca_bundle) {
            let certificate = certificate.map_err(|_| WebSocketTrustError::InvalidCaBundle)?;
            roots
                .add(certificate)
                .map_err(|_| WebSocketTrustError::InvalidCaBundle)?;
            certificate_count += 1;
        }
        if certificate_count == 0 {
            return Err(WebSocketTrustError::EmptyCaBundle);
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .with_platform_verifier()
            .map_err(WebSocketTrustError::TlsConfiguration)?
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

pub(crate) enum ReqwestTrustError {
    InvalidCaBundle(reqwest::Error),
    EmptyCaBundle,
}

pub(crate) enum WebSocketTrustError {
    InvalidCaBundle,
    EmptyCaBundle,
    TlsConfiguration(rustls::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsFailureKind {
    CertificateUntrusted,
    CertificateHostnameMismatch,
    CertificateExpired,
    VersionUnsupported,
    Handshake,
}

pub(crate) fn classify_tls_error(error: &rustls::Error) -> TlsFailureKind {
    use rustls::CertificateError;
    match error {
        rustls::Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => TlsFailureKind::CertificateExpired,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => TlsFailureKind::CertificateHostnameMismatch,
        rustls::Error::InvalidCertificate(CertificateError::Other(error)) => {
            classify_platform_certificate_error(error)
                .unwrap_or(TlsFailureKind::CertificateUntrusted)
        }
        rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
            TlsFailureKind::CertificateUntrusted
        }
        rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerDoesNotSupportTls12Or13
            | rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
            | rustls::PeerIncompatible::Tls12NotOffered
            | rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        )
        | rustls::Error::InvalidMessage(rustls::InvalidMessage::UnknownProtocolVersion)
        | rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion) => {
            TlsFailureKind::VersionUnsupported
        }
        _ => TlsFailureKind::Handshake,
    }
}

fn classify_platform_certificate_error(error: &rustls::OtherError) -> Option<TlsFailureKind> {
    #[cfg(target_vendor = "apple")]
    {
        // rustls-platform-verifier currently erases unhandled Apple
        // certificate failures into OtherError, but retains the stable
        // Security.framework OSStatus. Match only errSecCertificateExpired;
        // every unknown native error still fails closed as untrusted.
        if error.to_string().ends_with(": -67818") {
            return Some(TlsFailureKind::CertificateExpired);
        }
    }
    let _ = error;
    None
}

pub(crate) fn find_error_in_tree<'error, E: std::error::Error + 'static>(
    error: &'error (dyn std::error::Error + 'static),
    remaining_depth: usize,
) -> Option<&'error E> {
    if let Some(found) = error.downcast_ref::<E>() {
        return Some(found);
    }
    if remaining_depth == 0 {
        return None;
    }
    // TLS stacks can wrap a rustls error in nested io::Error values while
    // exposing only the outer io::Error through Error::source(). Inspect the
    // owned inner error as well so classification remains type-based.
    if let Some(io_error) = error.downcast_ref::<std::io::Error>()
        && let Some(inner) = io_error.get_ref()
        && let Some(found) = find_error_in_tree::<E>(inner, remaining_depth - 1)
    {
        return Some(found);
    }
    error
        .source()
        .and_then(|source| find_error_in_tree::<E>(source, remaining_depth - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustls_failures_map_to_the_stable_tls_contract() {
        let cases = [
            (
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
                TlsFailureKind::CertificateUntrusted,
            ),
            (
                rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
                TlsFailureKind::CertificateHostnameMismatch,
            ),
            (
                rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
                TlsFailureKind::CertificateExpired,
            ),
            (
                rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion),
                TlsFailureKind::VersionUnsupported,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify_tls_error(&error), expected);
        }

        #[cfg(target_vendor = "apple")]
        assert_eq!(
            classify_tls_error(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                    std::io::Error::other("certificate is expired: -67818"),
                ))),
            )),
            TlsFailureKind::CertificateExpired
        );
    }
}
