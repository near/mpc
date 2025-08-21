use crate::p2p::constants::DUMMY_ISSUER_PRIVATE_KEY;
use crate::p2p::keys::raw_ed25519_secret_key_to_keypair;
use crate::p2p::participants::ParticipantIdentities;
use crate::primitives::ParticipantId;
use anyhow::Context;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, CommonState, ServerConfig};
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Configures TLS server and client to properly perform TLS handshakes.
/// On the server side it expects a client to provide a certificate that
/// presents a public key that matches one of the participants in the MPC
/// network. On the client side it expects the server to present a
/// certificate that presents a public key that matches the expected participant
/// being connected to.
pub(crate) fn configure_tls(
    p2p_private_key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
    // The issuer is a dummy certificate authority that every node trusts.
    let issuer_signer = rcgen::KeyPair::from_pem(DUMMY_ISSUER_PRIVATE_KEY)?;
    let issuer_cert =
        rcgen::CertificateParams::new(vec!["root".to_string()])?.self_signed(&issuer_signer)?;

    // This is the keypair that is secret to this node, used in P2P handshakes.
    let p2p_key = raw_ed25519_secret_key_to_keypair(p2p_private_key)?;
    let p2p_key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p2p_key.serialize_der()));

    let p2p_cert = rcgen::CertificateParams::new(vec!["dummy".to_string()])?.signed_by(
        &p2p_key,
        &issuer_cert,
        &issuer_signer,
    )?;

    // Use a single trusted issuer.
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add(issuer_cert.der().clone())?;

    let client_verifier =
        WebPkiClientVerifier::builder(Arc::new(root_cert_store.clone())).build()?;

    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;
    // As a client, we verify that the server has a valid certificate signed by the
    // dummy issuer (this is required by rustls). When making the connection we also
    // check that the server has the right public key.
    let client_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;

    Ok((server_config.into(), client_config.into()))
}

pub(crate) fn verify_peer_identity(
    conn: &CommonState,
    participant_identities: &ParticipantIdentities,
) -> anyhow::Result<ParticipantId> {
    let Some(certs) = conn.peer_certificates() else {
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
    // The library doesn't recognize ED25519 keys, but that's fine, we'll compare the raw
    // bytes directly.
    let PublicKey::Unknown(public_key_data) = public_key else {
        anyhow::bail!(
            "Connection with unexpected public key type: {:?}",
            public_key
        );
    };
    let public_key = near_crypto::ED25519PublicKey(
        public_key_data
            .try_into()
            .context("Connection with public key of unexpected length")?,
    );
    let Some(peer_id) = participant_identities
        .key_to_participant_id
        .get(&near_crypto::PublicKey::ED25519(public_key))
    else {
        anyhow::bail!("Connection with unknown public key");
    };
    Ok(*peer_id)
}
