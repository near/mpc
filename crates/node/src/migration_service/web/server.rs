use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use near_mpc_crypto_types::Keyset;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::metrics;
use crate::migration_service::{
    types::MigrationInfo,
    web::{authentication::authenticate_peer, serialization::serialize_and_encrypt_keyshares},
};

use super::{
    serialization::decrypt_and_deserialize_keyshares,
    types::{ExpectedPeerInfo, WebServerState},
};

pub(crate) async fn start_web_server(
    web_server_state: Arc<WebServerState>,
    bind_address: SocketAddr,
    migration_state_receiver: watch::Receiver<MigrationInfo>,
    p2p_private_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let (server_config, _client_config) = mpc_tls::tls::configure_tls(p2p_private_key)?;

    tracing::info!(?bind_address, "attempting to bind web server to address");

    let mut expected_peer_info_receiver =
        spawn_expected_peer_info_monitoring(migration_state_receiver).await;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(&bind_address).await?;
    tokio::spawn(async move {
        tracing::info!("handle incoming connections");
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let expected_peer = expected_peer_info_receiver.borrow_and_update().clone();
            let tls_acceptor = tls_acceptor.clone();
            let state_clone = web_server_state.clone();
            tokio::spawn(handle_stream(
                tls_acceptor,
                tcp_stream,
                state_clone,
                expected_peer,
            ));
        }
    });

    tracing::info!(address = %bind_address, "Successfully bound to address");
    Ok(())
}

async fn handle_stream(
    tls_acceptor: TlsAcceptor,
    tcp_stream: TcpStream,
    state: Arc<WebServerState>,
    expected_peer: ExpectedPeerInfo,
) -> anyhow::Result<()> {
    tracing::info!("Handle connection");
    let stream = tls_acceptor.accept(tcp_stream).await?;

    let Some(expected_pk) = expected_peer.expected_pk else {
        anyhow::bail!("not accepting connections without a Backup service info");
    };
    authenticate_peer(stream.get_ref().1, &expected_pk)
        .inspect_err(|err| tracing::error!(?err, "error authenticating client"))?;
    tracing::info!(
        "TLS handshake complete, backup service authenticated and encrypted channel established"
    );
    let http_protocol = hyper::server::conn::http1::Builder::new();

    tokio::select! {
        res = http_protocol.serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| handle_request(req, state.clone())),
        ) => {
            match res {
                Ok(_) => tracing::info!("connection closed gracefully"),
                Err(err) => tracing::error!("error serving connection: {err:?}"),
            }
        }
        _ = expected_peer.cancelled.cancelled() => {
            tracing::info!("dropping connection due to cancellation (change in migration info or cancellation of web server)");
        }
    }
    anyhow::Ok(())
}

async fn spawn_expected_peer_info_monitoring(
    mut migration_state_receiver: watch::Receiver<MigrationInfo>,
) -> watch::Receiver<ExpectedPeerInfo> {
    let current_info = migration_state_receiver.borrow_and_update().clone();
    let (sender, receiver) = watch::channel(ExpectedPeerInfo::from_migration(
        current_info,
        CancellationToken::new(),
    ));
    tokio::spawn(async move {
        loop {
            let res = migration_state_receiver.changed().await;
            sender.borrow().cancelled.cancel();
            if res.is_err() {
                tracing::info!("migration state sender dropped, cancelling peer info and exiting");
                return anyhow::Ok(());
            };
            let current_info = migration_state_receiver.borrow_and_update().clone();
            sender.send(ExpectedPeerInfo::from_migration(
                current_info,
                CancellationToken::new(),
            ))?;
        }
    });
    receiver
}

fn json_response(body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

#[derive(Debug, thiserror::Error)]
enum RecordBackupServedError {
    #[error("epoch id {0} does not fit in an i64 gauge")]
    EpochIdTooLargeForI64(u64),
    #[error("unix timestamp {0} does not fit in an i64 gauge")]
    TimestampTooLargeForI64(u64),
    #[error("system clock is before the unix epoch")]
    ClockBeforeUnixEpoch(#[from] SystemTimeError),
}

fn record_backup_served(keyset: &Keyset) -> Result<(), RecordBackupServedError> {
    let epoch_id = keyset.epoch_id.get();
    let epoch = i64::try_from(epoch_id)
        .map_err(|_| RecordBackupServedError::EpochIdTooLargeForI64(epoch_id))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timestamp =
        i64::try_from(now).map_err(|_| RecordBackupServedError::TimestampTooLargeForI64(now))?;

    metrics::MPC_LAST_BACKUP_SERVED_EPOCH.set(epoch);
    metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.set(timestamp);
    Ok(())
}

async fn handle_request(
    req: hyper::Request<Incoming>,
    state: Arc<WebServerState>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/hello") => Ok(Response::new(Full::new(Bytes::from_static(
            b"Hello, world!",
        )))),
        ("GET", "/get_keyshares") => {
            tracing::info!("received get_keyshares request");
            let whole_body = req.into_body().collect().await.map(|body| body.to_bytes());
            match whole_body {
                Ok(bytes) => match serde_json::from_slice::<Keyset>(&bytes) {
                    Ok(keyset) => {
                        let keyshares = match state
                            .keyshare_storage
                            .read()
                            .await
                            .get_keyshares(&keyset)
                            .await
                        {
                            Ok(keyshares) => keyshares,
                            Err(err) => {
                                let msg = err.to_string();
                                tracing::error!(msg);
                                return Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Full::new(Bytes::from_static(b"Failed to get keyshares")))
                                    .unwrap());
                            }
                        };
                        match serialize_and_encrypt_keyshares(
                            &keyshares,
                            &state.backup_encryption_key,
                        ) {
                            Ok(encrypted_keyshares) => {
                                let response = json_response(encrypted_keyshares);
                                // A domain-less keyset yields no keyshares: nothing was backed up.
                                if !keyshares.is_empty()
                                    && let Err(err) = record_backup_served(&keyset)
                                {
                                    tracing::error!(?err, "failed to record served backup");
                                }
                                Ok(response)
                            }
                            Err(err) => {
                                tracing::error!(?err, "serialization or encryption error");
                                Ok(json_response(
                                    "internal error serializing or encrypting keyshares"
                                        .to_string(),
                                ))
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(?err, "received invalid keyset");
                        Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::new(Bytes::from(format!("Invalid keyset: {err}"))))
                            .unwrap())
                    }
                },
                Err(err) => {
                    tracing::error!(?err, "failed to read body");
                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from(format!(
                            "Failed to read body: {err}"
                        ))))
                        .unwrap())
                }
            }
        }
        ("PUT", "/set_keyshares") => {
            tracing::info!("received set_keyshares request");
            let whole_body = req.into_body().collect().await.map(|body| body.to_bytes());
            match whole_body {
                Ok(bytes) => Ok(handle_set_keyshares(&bytes, &state)),
                Err(err) => {
                    tracing::error!(?err, "set_keyshares: failed to read body");
                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from(format!(
                            "Failed to read body: {err}"
                        ))))
                        .unwrap())
                }
            }
        }
        _ => {
            let mut not_found = Response::new(Full::new(Bytes::from_static(b"Not Found")));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

/// Hands received keyshares to the onboarding loop. Every outcome is logged: an operator
/// watching a migration otherwise cannot tell a transfer from a rejected or empty one.
fn handle_set_keyshares(body: &[u8], state: &WebServerState) -> Response<Full<Bytes>> {
    let keyshares = match decrypt_and_deserialize_keyshares(body, &state.backup_encryption_key) {
        Ok(keyshares) => keyshares,
        Err(err) => {
            tracing::error!(?err, "set_keyshares rejected: invalid json or encryption");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!(
                    "Invalid Json or encryption: {err}"
                ))))
                .unwrap();
        }
    };

    // The onboarding loop skips an empty set, so accepting one imports nothing.
    if keyshares.is_empty() {
        tracing::warn!("set_keyshares received no keyshares, nothing will be imported");
    }

    let num_keyshares = keyshares.len();
    if state.import_keyshares_sender.send(keyshares).is_err() {
        let msg = "keyshares receiver channel is closed".to_string();
        tracing::error!(msg);
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from(msg)))
            .unwrap();
    }

    tracing::info!(num_keyshares, "set_keyshares accepted keyshares");
    Response::new(Full::new(Bytes::from_static(b"Keyshares received.")))
}

#[cfg(test)]
mod tests {
    use crate::keyshare::{Keyshare, generate_key_storage_config, test_utils::KeysetBuilder};
    use crate::metrics;
    use crate::migration_service::{
        types::MigrationInfo,
        web::{
            serialization::serialize_and_encrypt_keyshares,
            server::{
                RecordBackupServedError, WebServerState, handle_set_keyshares,
                record_backup_served, spawn_expected_peer_info_monitoring,
            },
        },
    };

    use assert_matches::assert_matches;
    use ed25519_dalek::SigningKey;
    use hyper::StatusCode;
    use mpc_primitives::EpochId;
    use near_mpc_contract_interface::types::{BackupServiceInfo, Ed25519PublicKey};
    use near_mpc_crypto_types::Keyset;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use serial_test::serial;
    use std::sync::Arc;
    use tokio::sync::{RwLock, watch};
    use tracing_test::traced_test;

    const BACKUP_ENCRYPTION_KEY: [u8; 32] = [7u8; 32];

    /// The returned [`TempDir`](tempfile::TempDir) backs the keyshare storage and must outlive it.
    async fn web_server_state() -> (
        WebServerState,
        watch::Receiver<Vec<Keyshare>>,
        tempfile::TempDir,
    ) {
        let (import_keyshares_sender, import_keyshares_receiver) = watch::channel(vec![]);
        let (config, tempdir) = generate_key_storage_config();
        let keyshare_storage = config
            .create()
            .await
            .expect("keyshare storage should be creatable in a temp dir");
        (
            WebServerState {
                import_keyshares_sender,
                keyshare_storage: Arc::new(RwLock::new(keyshare_storage)),
                backup_encryption_key: BACKUP_ENCRYPTION_KEY,
            },
            import_keyshares_receiver,
            tempdir,
        )
    }

    fn encrypted_body(keyshares: &[Keyshare]) -> String {
        serialize_and_encrypt_keyshares(keyshares, &BACKUP_ENCRYPTION_KEY)
            .expect("keyshares should be serializable")
    }

    fn make_migration_info_with_key(key: &SigningKey) -> MigrationInfo {
        MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: Ed25519PublicKey::from(&key.verifying_key()),
            }),
            active_migration: true,
        }
    }
    #[tokio::test]
    async fn test_spawn_expected_peer_info_monitoring_updates() {
        let key1 = SigningKey::generate(&mut rand::thread_rng());
        let migration_info1 = make_migration_info_with_key(&key1);

        let (migration_info_sender, migration_info_receiver) = watch::channel(migration_info1);
        let expected_peer_rx = spawn_expected_peer_info_monitoring(migration_info_receiver).await;

        let initial = expected_peer_rx.borrow().clone();
        let expected = Some(key1.verifying_key());
        assert_eq!(initial.expected_pk, expected);
        assert!(!initial.cancelled.is_cancelled());

        let key2 = SigningKey::generate(&mut rand::thread_rng());
        let migration_info2 = make_migration_info_with_key(&key2);

        // Send an updated migration info
        migration_info_sender.send(migration_info2.clone()).unwrap();

        // wait for cancellation
        initial.cancelled.cancelled().await;

        let updated = expected_peer_rx.borrow().clone();
        let expected_pk = Some(key2.verifying_key());
        assert_eq!(updated.expected_pk, expected_pk);

        // Ensure the info is cancelled if the sender is dropped
        drop(migration_info_sender);
        updated.cancelled.cancelled().await;
    }

    #[serial(backup_metrics)]
    #[test]
    #[expect(non_snake_case)]
    fn record_backup_served__should_fail_and_leave_gauges_untouched_for_an_unrepresentable_epoch() {
        // Given
        let keyset = Keyset::new(EpochId::new(u64::MAX), Vec::new());
        let epoch_before = metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get();
        let timestamp_before = metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get();

        // When
        let res = record_backup_served(&keyset);

        // Then
        assert_matches!(
            res,
            Err(RecordBackupServedError::EpochIdTooLargeForI64(epoch)) if epoch == u64::MAX
        );
        assert_eq!(metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get(), epoch_before);
        assert_eq!(
            metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get(),
            timestamp_before
        );
    }

    #[traced_test]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn handle_set_keyshares__should_log_the_number_of_accepted_keyshares() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let keyset = KeysetBuilder::new_populated(1, 2, &mut rng);
        let (state, mut receiver, _tempdir) = web_server_state().await;
        let body = encrypted_body(keyset.keyshares());

        // When
        let response = handle_set_keyshares(body.as_bytes(), &state);

        // Then
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*receiver.borrow_and_update(), keyset.keyshares().to_vec());
        assert!(logs_contain("set_keyshares accepted keyshares"));
        assert!(logs_contain("num_keyshares=2"));
    }

    #[traced_test]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn handle_set_keyshares__should_warn_when_the_request_carries_no_keyshares() {
        // Given
        let (state, _receiver, _tempdir) = web_server_state().await;
        let body = encrypted_body(&[]);

        // When
        let response = handle_set_keyshares(body.as_bytes(), &state);

        // Then
        assert_eq!(response.status(), StatusCode::OK);
        assert!(logs_contain(
            "set_keyshares received no keyshares, nothing will be imported"
        ));
    }

    #[traced_test]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn handle_set_keyshares__should_log_a_rejected_request() {
        // Given
        let (state, _receiver, _tempdir) = web_server_state().await;

        // When
        let response = handle_set_keyshares(b"not encrypted keyshares", &state);

        // Then
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(logs_contain(
            "set_keyshares rejected: invalid json or encryption"
        ));
    }
}
