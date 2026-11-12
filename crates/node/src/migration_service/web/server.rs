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
        ("GET", "/get_keyshares") => Ok(handle_get_keyshares(req.into_body(), &state).await),
        ("PUT", "/set_keyshares") => Ok(handle_set_keyshares(req.into_body(), &state).await),
        _ => Ok(error_response(StatusCode::NOT_FOUND, "Not Found")),
    }
}

async fn handle_get_keyshares<B>(body: B, state: &WebServerState) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: std::fmt::Debug + std::fmt::Display,
{
    tracing::info!("received get_keyshares request");
    if !*state.onboarded.borrow() {
        tracing::warn!("get_keyshares rejected: node is not onboarded");
        return error_response(StatusCode::FORBIDDEN, "Node is not onboarded");
    }
    let bytes = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(err) => {
            tracing::error!(?err, "get_keyshares: failed to read body");
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("Failed to read body: {err}"),
            );
        }
    };
    let keyset: Keyset = match serde_json::from_slice(&bytes) {
        Ok(keyset) => keyset,
        Err(err) => {
            tracing::error!(?err, "get_keyshares rejected: invalid keyset");
            return error_response(StatusCode::BAD_REQUEST, format!("Invalid keyset: {err}"));
        }
    };
    let keyshares = match state
        .keyshare_storage
        .read()
        .await
        .get_keyshares(&keyset)
        .await
    {
        Ok(keyshares) => keyshares,
        Err(err) => {
            tracing::error!(?err, "failed to get keyshares");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get keyshares");
        }
    };
    let encrypted_keyshares =
        match serialize_and_encrypt_keyshares(&keyshares, &state.backup_encryption_key) {
            Ok(encrypted_keyshares) => encrypted_keyshares,
            Err(err) => {
                tracing::error!(?err, "serialization or encryption error");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to serialize or encrypt keyshares",
                );
            }
        };
    // A domain-less keyset yields no keyshares: nothing was backed up.
    if !keyshares.is_empty()
        && let Err(err) = record_backup_served(&keyset)
    {
        tracing::error!(?err, "failed to record served backup");
    }
    json_response(encrypted_keyshares)
}

/// Hands received keyshares to the onboarding loop, logging each outcome.
async fn handle_set_keyshares<B>(body: B, state: &WebServerState) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: std::fmt::Debug + std::fmt::Display,
{
    tracing::info!("received set_keyshares request");
    let bytes = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(err) => {
            tracing::error!(?err, "set_keyshares: failed to read body");
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("Failed to read body: {err}"),
            );
        }
    };

    let keyshares = match decrypt_and_deserialize_keyshares(&bytes, &state.backup_encryption_key) {
        Ok(keyshares) => keyshares,
        Err(err) => {
            tracing::error!(?err, "set_keyshares rejected: invalid json or encryption");
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid Json or encryption: {err}"),
            );
        }
    };

    if keyshares.is_empty() {
        tracing::warn!("set_keyshares received no keyshares, nothing will be imported");
    }

    let num_keyshares = keyshares.len();
    if state.import_keyshares_sender.send(keyshares).is_err() {
        let msg = "keyshares receiver channel is closed";
        tracing::error!(msg);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, msg);
    }

    tracing::info!(num_keyshares, "set_keyshares accepted keyshares");
    Response::new(Full::new(Bytes::from_static(b"Keyshares received.")))
}

fn error_response(status: StatusCode, msg: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(msg.into()))
        .unwrap()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::keyshare::{Keyshare, generate_key_storage_config, test_utils::KeysetBuilder};
    use crate::metrics;
    use crate::migration_service::{
        types::MigrationInfo,
        web::{
            serialization::serialize_and_encrypt_keyshares,
            server::{
                RecordBackupServedError, WebServerState, handle_get_keyshares,
                handle_set_keyshares, record_backup_served, spawn_expected_peer_info_monitoring,
            },
        },
    };

    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use http_body_util::Full;
    use hyper::StatusCode;
    use mpc_primitives::EpochId;
    use near_mpc_contract_interface::types::{BackupServiceInfo, Ed25519PublicKey};
    use near_mpc_crypto_types::Keyset;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use rstest::rstest;
    use serial_test::serial;
    use std::{assert_matches, sync::Arc};
    use tokio::sync::{RwLock, watch};

    const BACKUP_ENCRYPTION_KEY: [u8; 32] = [7u8; 32];

    /// The returned [`tempfile::TempDir`] backs the keyshare storage and must outlive it.
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
                onboarded: watch::channel(false).1,
            },
            import_keyshares_receiver,
            tempdir,
        )
    }

    fn encrypted_body(keyshares: &[Keyshare]) -> String {
        serialize_and_encrypt_keyshares(keyshares, &BACKUP_ENCRYPTION_KEY)
            .expect("keyshares should be serializable")
    }

    fn full_body(body: String) -> Full<Bytes> {
        Full::new(Bytes::from(body))
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

    #[rstest]
    #[case::before_onboarding(false, StatusCode::FORBIDDEN)]
    #[case::after_onboarding(true, StatusCode::OK)]
    #[tokio::test]
    async fn handle_get_keyshares__should_export_keyshares_only_once_onboarded(
        #[case] onboarded: bool,
        #[case] expected_status: StatusCode,
    ) {
        // Given
        let (mut state, _receiver, _tempdir) = web_server_state().await;
        state.onboarded = watch::channel(onboarded).1;
        let body = serde_json::to_string(&KeysetBuilder::new(1).keyset()).unwrap();

        // When
        let response = handle_get_keyshares(full_body(body), &state).await;

        // Then
        assert_eq!(response.status(), expected_status);
    }

    #[tokio::test]
    async fn handle_set_keyshares__should_forward_the_received_keyshares() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let keyset = KeysetBuilder::new_populated(1, 2, &mut rng);
        let (state, mut receiver, _tempdir) = web_server_state().await;
        let body = encrypted_body(keyset.keyshares());

        // When
        let response = handle_set_keyshares(full_body(body), &state).await;

        // Then
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*receiver.borrow_and_update(), keyset.keyshares().to_vec());
    }

    #[tokio::test]
    async fn handle_set_keyshares__should_accept_a_request_carrying_no_keyshares() {
        // Given
        let (state, receiver, _tempdir) = web_server_state().await;
        let body = encrypted_body(&[]);

        // When
        let response = handle_set_keyshares(full_body(body), &state).await;

        // Then
        assert_eq!(response.status(), StatusCode::OK);
        assert!(receiver.has_changed().unwrap());
    }

    #[tokio::test]
    async fn handle_set_keyshares__should_reject_an_undecryptable_body() {
        // Given
        let (state, receiver, _tempdir) = web_server_state().await;

        // When
        let response =
            handle_set_keyshares(Full::new(Bytes::from_static(b"not encrypted")), &state).await;

        // Then
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!receiver.has_changed().unwrap());
    }

    #[tokio::test]
    async fn handle_set_keyshares__should_fail_when_the_import_receiver_is_gone() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let keyset = KeysetBuilder::new_populated(1, 1, &mut rng);
        let (state, receiver, _tempdir) = web_server_state().await;
        let body = encrypted_body(keyset.keyshares());
        drop(receiver);

        // When
        let response = handle_set_keyshares(full_body(body), &state).await;

        // Then
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
