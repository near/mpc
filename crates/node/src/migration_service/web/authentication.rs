use ed25519_dalek::VerifyingKey;

/// Authenticates the peer by verifying its TLS public key matches the expected one.
///
/// Extracts the peer’s public key from the TLS state and compares it with
/// `expected_peer_public_key`. Returns an error if they differ.
pub fn authenticate_peer(
    common_state: &rustls::CommonState,
    expected_peer_public_key: &VerifyingKey,
) -> anyhow::Result<()> {
    let peer_public_key = mpc_tls::tls::extract_public_key(common_state)?;

    if peer_public_key != *expected_peer_public_key {
        tracing::info!(
            ?expected_peer_public_key,
            ?peer_public_key,
            "closing connection, public key mismatch"
        );
        anyhow::bail!("closing connection, public key mismatch");
    }
    tracing::info!("TLS handshake complete, peer authenticated and encrypted channel established.");
    Ok(())
}
