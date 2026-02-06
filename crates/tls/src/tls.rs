use crate::constants;
use crate::keygen::raw_ed25519_secret_key_to_keypair;
use anyhow::Context;
use rustls::pki_types::PrivateKeyDer;
use rustls::{pki_types::PrivatePkcs8KeyDer, server::WebPkiClientVerifier};
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate};

struct SelfSignedCert {
    keypair: rcgen::KeyPair,
    self_signed_certificate: rcgen::Certificate,
}

/// Creates a self-signed certificate using the embedded `constants::DUMMY_ISSUER_PRIVATE_KEY`.
/// The certificate will have `constants::ROOT_CERT` as its subject name.
fn self_signed_dummy_certificate() -> anyhow::Result<SelfSignedCert> {
    let dummy_keypair: rcgen::KeyPair =
        rcgen::KeyPair::from_pem(constants::DUMMY_ISSUER_PRIVATE_KEY)?;
    let self_signed_certificate =
        rcgen::CertificateParams::new(vec![constants::ROOT_CERT.to_string()])?
            .self_signed(&dummy_keypair)?;
    Ok(SelfSignedCert {
        keypair: dummy_keypair,
        self_signed_certificate,
    })
}

/// Issues a new certificate for the given `public_key`,
/// signed by the provided `issuer_cert`.
/// The new certificate will have `constants::SERVER_NAME` as its subject name.
fn issue_peer_certificate(
    issuer_cert: &SelfSignedCert,
    public_key: &impl rcgen::PublicKeyData,
) -> anyhow::Result<rcgen::Certificate> {
    Ok(
        rcgen::CertificateParams::new(vec![constants::SERVER_NAME.to_string()])?.signed_by(
            public_key,
            &issuer_cert.self_signed_certificate,
            &issuer_cert.keypair,
        )?,
    )
}

/// Builds a [`rustls::server::ServerConfig`] for a peer-to-peer server.
///
/// The returned configuration:
/// - Restricts protocol versions to `constants::TLS_PROTOCOL_VERSION`.
/// - Uses `p2p_cert` and `p2p_private_key` as the server's identity (certificate + private key).
/// - Enforces **mutual TLS (mTLS)** by requiring connecting clients to present certificates
///   that chain back to one of the roots in `root_cert_store`.
///
/// # Parameters
/// - `root_cert_store`: Root certificate store used to verify client certificates.
/// - `p2p_cert`: Leaf certificate representing this server in the P2P network.
/// - `p2p_private_key`: DER-encoded private key matching the public key contained in `p2p_cert`.
///
/// # Returns
/// A `ServerConfig`, suitable for constructing a
/// [`tokio_rustls::TlsAcceptor`].
///
/// # Errors
/// Returns an error if:
/// - Building the client verifier fails (e.g., invalid `root_cert_store`),
/// - Or if the server certificate + private key cannot be combined into a valid identity.
fn server_tls_config(
    root_cert_store: Arc<rustls::RootCertStore>,
    p2p_cert: &rcgen::Certificate,
    p2p_private_key: &PrivateKeyDer,
) -> anyhow::Result<rustls::server::ServerConfig> {
    let client_verifier = WebPkiClientVerifier::builder(root_cert_store).build()?;
    Ok(
        rustls::ServerConfig::builder_with_protocol_versions(&[constants::TLS_PROTOCOL_VERSION])
            .with_client_cert_verifier(client_verifier) // enforcing mTLS
            .with_single_cert(vec![p2p_cert.der().clone()], p2p_private_key.clone_key())?,
    )
}

/// Builds a [`rustls::client::ClientConfig`] for peer-to-peer connections.
///
/// The returned configuration:
/// - Restricts protocol versions to `constants::TLS_PROTOCOL_VERSION` (e.g., TLS 1.3 only).
/// - Trusts servers presenting certificates that chain back to the provided `root_cert_store`
///   (in this setup, the dummy issuer).
/// - Configures the client to authenticate itself with `p2p_cert` and `p2p_private_key`,
///   so that both peers verify each other’s identity (mutual TLS).
///
/// # Parameters
/// - `root_cert_store`: Store of trusted root certificates used to verify server certificates.
/// - `p2p_cert`: Client certificate representing this node in the P2P network.
/// - `p2p_private_key`: DER-encoded private key matching the public key contained in `p2p_cert`.
///
/// # Returns
/// A configured [`rustls::client::ClientConfig`] ready for constructing a
/// [`tokio_rustls::TlsConnector`].
///
/// # Errors
/// Returns an error if the provided client certificate and private key do not form a valid identity.
fn client_tls_config(
    root_cert_store: Arc<rustls::RootCertStore>,
    p2p_cert: &rcgen::Certificate,
    p2p_private_key: &PrivateKeyDer,
) -> anyhow::Result<rustls::client::ClientConfig> {
    Ok(
        rustls::ClientConfig::builder_with_protocol_versions(&[constants::TLS_PROTOCOL_VERSION])
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(vec![p2p_cert.der().clone()], p2p_private_key.clone_key())?,
    )
}

/// Builds both server and client TLS configurations for a P2P node.
///
/// The configuration process:
/// - Generates a dummy self-signed certificate authority and adds it to the trusted root store.
/// - Derives a keypair from the provided `p2p_private_key`.
/// - Issues a peer certificate for that keypair, signed by the dummy authority.
/// - Converts the private key into DER format for use with rustls.
/// - Constructs:
///   - a [`rustls::server::ServerConfig`] that requires client certificates chaining to the dummy root (mTLS),
///   - a [`rustls::client::ClientConfig`] that presents the issued peer certificate and trusts the same root.
///
/// # Parameters
/// - `p2p_private_key`: The Ed25519 secret key of this node, used as its identity in P2P handshakes.
///
/// # Returns
/// A tuple `(ServerConfig, ClientConfig)` containing the TLS configurations
/// for server and client roles.
///
/// # Errors
/// Returns an error if certificate creation, key conversion, or TLS configuration fails.
pub fn configure_tls(
    p2p_private_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<(rustls::server::ServerConfig, rustls::client::ClientConfig)> {
    // Generate a self-signed certificate from the dummy key.
    let dummy_issuer_cert: SelfSignedCert = self_signed_dummy_certificate()?;
    // Add the dummy issuer to the trusted certificate list.
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add(dummy_issuer_cert.self_signed_certificate.der().clone())?;
    let root_cert_store = Arc::new(root_cert_store);

    // This is the keypair that is secret to this node, used in P2P handshakes.
    let p2p_keypair: rcgen::KeyPair = raw_ed25519_secret_key_to_keypair(p2p_private_key)?;
    // Sign the public key of the secure keypair by the dummy certicificate authority
    let peer_certificate = issue_peer_certificate(&dummy_issuer_cert, &p2p_keypair)?;

    // Convert private key to rustls DER
    let p2p_private_key: PrivateKeyDer = rustls::pki_types::PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(p2p_keypair.serialize_der()),
    );

    let server_config =
        server_tls_config(root_cert_store.clone(), &peer_certificate, &p2p_private_key)?;
    let client_config = client_tls_config(root_cert_store, &peer_certificate, &p2p_private_key)?;

    Ok((server_config, client_config))
}

/// Extracts the peer’s Ed25519 public key from a TLS connection state.
///
/// This function inspects the peer certificate provided during the TLS handshake and
/// returns the raw Ed25519 public key contained within it.
///
/// The extraction process:
/// - Ensures that the peer presented exactly one certificate.
/// - Parses the certificate as DER and extracts its public key.
/// - Validates that the key is of the expected type (Ed25519, handled as `Unknown` by the parser).
/// - Converts the raw key bytes into a [`ed25519_dalek::VerifyingKey`].
///
/// # Parameters
/// - `common_state`: A reference to the [`rustls::CommonState`] of the TLS connection.
///
/// # Returns
/// The peer’s Ed25519 public key if extraction succeeds.
///
/// # Errors
/// Returns an error if:
/// - No peer certificate is present,
/// - More than one certificate is provided,
/// - The certificate cannot be parsed,
/// - The certificate contains an invalid or unsupported public key,
/// - The key length is unexpected.
pub fn extract_public_key(
    common_state: &rustls::CommonState,
) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    let Some(certs) = common_state.peer_certificates() else {
        anyhow::bail!("Connection without peer identity");
    };
    if certs.len() != 1 {
        anyhow::bail!("Connection with unexpected number of certificates");
    };
    let Ok(cert) = X509Certificate::from_der(&certs[0]) else {
        anyhow::bail!("Connection with invalid certificate");
    };
    let Ok(public_key) = cert.1.public_key().parsed() else {
        anyhow::bail!("Connection with invalid public key");
    };

    // The x509_parser library doesn't recognize ED25519 keys, but that's fine, we'll compare the raw
    // bytes directly.
    let x509_parser::public_key::PublicKey::Unknown(public_key_data) = public_key else {
        anyhow::bail!("Connection with unexpected public key type: {public_key:?}");
    };

    let public_key_bytes = public_key_data
        .try_into()
        .context("Connection with public key of unexpected length")?;

    let public_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
        .context("Connection with invalid public key.")?;

    Ok(public_key)
}
