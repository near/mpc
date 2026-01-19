use std::{convert::Infallible, sync::Arc};

use hyper::{service::service_fn, Body, Response, StatusCode};
use mpc_contract::primitives::key_state::Keyset;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    config::WebUIConfig,
    migration_service::{
        types::MigrationInfo,
        web::{authentication::authenticate_peer, serialization::serialize_and_encrypt_keyshares},
    },
};

use super::{
    serialization::decrypt_and_deserialize_keyshares,
    types::{ExpectedPeerInfo, WebServerState},
};

pub(crate) async fn start_web_server(
    web_server_state: Arc<WebServerState>,
    config: WebUIConfig,
    migration_state_receiver: watch::Receiver<MigrationInfo>,
    p2p_private_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let (server_config, _client_config) = mpc_tls::tls::configure_tls(p2p_private_key)?;

    tracing::info!(
        host = %config.host,
        port = %config.port,
        "attempting to bind web server to host",
    );

    let mut expected_peer_info_receiver =
        spawn_expected_peer_info_monitoring(migration_state_receiver).await;

    let bind_address = format!("{}:{}", config.host, config.port);
    tracing::info!(address = %bind_address, "binding to address");

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
    let http_protocol = hyper::server::conn::Http::new();

    tokio::select! {
        res = http_protocol.serve_connection(
            stream,
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

async fn handle_request(
    req: hyper::Request<Body>,
    state: Arc<WebServerState>,
) -> Result<hyper::Response<Body>, Infallible> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/hello") => Ok(Response::new(Body::from("Hello, world!"))),
        ("GET", "/get_keyshares") => {
            tracing::info!("received get_keyshares request");
            let whole_body = hyper::body::to_bytes(req.into_body()).await;
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
                                    .body(Body::from("Failed to get keyshares"))
                                    .unwrap());
                            }
                        };
                        let resp = serialize_and_encrypt_keyshares(
                            &keyshares,
                            &state.backup_encryption_key,
                        )
                        .unwrap_or_else(|err| {
                            tracing::error!(?err, "serializtion or encryption error");
                            "internal error serializing or encrypting keyshares".to_string()
                        });
                        let mut response = Response::new(Body::from(resp));
                        response.headers_mut().insert(
                            hyper::header::CONTENT_TYPE,
                            hyper::header::HeaderValue::from_static("application/json"),
                        );
                        Ok(response)
                    }
                    Err(err) => {
                        tracing::error!(?err, "received invalid keyset");
                        Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(format!("Invalid keyset: {err}")))
                            .unwrap())
                    }
                },
                Err(err) => {
                    tracing::error!(?err, "failed to read body");
                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(format!("Failed to read body: {err}")))
                        .unwrap())
                }
            }
        }
        ("PUT", "/set_keyshares") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await;
            match whole_body {
                Ok(bytes) => {
                    match decrypt_and_deserialize_keyshares(&bytes, &state.backup_encryption_key) {
                        Ok(new_keyshares) => {
                            if state.import_keyshares_sender.send(new_keyshares).is_err() {
                                let msg = "keyshares receiver channel is closed".to_string();
                                tracing::error!(msg);
                                Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(msg))
                                    .unwrap())
                            } else {
                                Ok(Response::new(Body::from("Keyshares received.")))
                            }
                        }
                        Err(err) => Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(format!("Invalid Json or encryption: {err}")))
                            .unwrap()),
                    }
                }
                Err(err) => Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Failed to read body: {err}")))
                    .unwrap()),
            }
        }
        _ => {
            let mut not_found = Response::new(Body::from("Not Found"));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        migration_service::{
            types::MigrationInfo, web::server::spawn_expected_peer_info_monitoring,
        },
        trait_extensions::convert_to_contract_dto::IntoContractInterfaceType,
    };

    use ed25519_dalek::SigningKey;
    use mpc_contract::node_migrations::BackupServiceInfo;
    use tokio::sync::watch;

    fn make_migration_info_with_key(key: &SigningKey) -> MigrationInfo {
        MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: key.verifying_key().into_contract_interface_type(),
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
}
