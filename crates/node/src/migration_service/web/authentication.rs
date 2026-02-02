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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use mpc_tls::tls::configure_tls;

    use crate::migration_service::web::authentication::authenticate_peer;

    #[tokio::test]
    async fn test_authenticate_peer() {
        use rand::SeedableRng as _;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let server_key = SigningKey::generate(&mut rng);
        let client_key = SigningKey::generate(&mut rng);
        let other_pk = SigningKey::generate(&mut rng).verifying_key();

        let (server_config, _) = configure_tls(&server_key).unwrap();
        let (_, client_config) = configure_tls(&client_key).unwrap();

        let server_config = Arc::new(server_config);
        let client_config = Arc::new(client_config);

        let (client_socket, server_socket) = tokio::io::duplex(1024);

        let server_task = tokio::spawn({
            let server_config = server_config.clone();
            async move {
                let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                let tls_stream = tls_acceptor.accept(server_socket).await?;
                Ok::<_, anyhow::Error>(tls_stream)
            }
        });

        let tls_connector = tokio_rustls::TlsConnector::from(client_config);
        let _client_stream = tls_connector
            .connect("dummy".try_into().unwrap(), client_socket)
            .await
            .unwrap();

        let server_stream = server_task.await.unwrap().unwrap();

        let _ = authenticate_peer(server_stream.get_ref().1, &other_pk)
            .expect_err("Authentication should fail for a different public key");
        let _ = authenticate_peer(server_stream.get_ref().1, &client_key.verifying_key())
            .expect("Authentication should succeed for the client key");
    }
}
