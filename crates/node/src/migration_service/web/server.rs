use std::{convert::Infallible, sync::Arc};

use hyper::{service::service_fn, Body, Response, StatusCode};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    config::WebUIConfig,
    keyshare::Keyshare,
    migration_service::{types::MigrationInfo, web::authentication::authenticate_peer},
};

use super::types::{ExpectedPeerInfo, WebServerState};

async fn spawn_expected_peer_info_monitoring(
    cancellation_token: CancellationToken,
    mut migration_state_receiver: watch::Receiver<MigrationInfo>,
) -> watch::Receiver<ExpectedPeerInfo> {
    let current_info = migration_state_receiver.borrow_and_update().clone();
    let mut info_cancelled = cancellation_token.child_token();
    let (sender, receiver) = watch::channel(ExpectedPeerInfo::from_migration(
        current_info,
        info_cancelled.clone(),
    ));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => { return Ok(()); }
                res = migration_state_receiver.changed() => {
                    info_cancelled.cancel();
                    if res.is_err() {
                        tracing::info!("migration state sender dropped, cancelling peer info and exiting");
                        return anyhow::Ok(());
                    };
                    let current_info = migration_state_receiver.borrow_and_update().clone();
                    info_cancelled = cancellation_token.child_token();
                    sender.send(ExpectedPeerInfo::from_migration(current_info, info_cancelled.clone()))?;
                },
            }
        }
    });
    return receiver;
}

pub async fn start_web_server(
    web_server_state: Arc<WebServerState>,
    config: WebUIConfig,
    migration_state_receiver: watch::Receiver<MigrationInfo>,
    p2p_private_key: &ed25519_dalek::SigningKey,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let (server_config, _client_config) = mpc_tls::tls::configure_tls(p2p_private_key)?;

    tracing::info!(
        host = %config.host,
        port = %config.port,
        "Attempting to bind web server to host",
    );

    let mut expected_peer_info_receiver = spawn_expected_peer_info_monitoring(
        cancellation_token.child_token(),
        migration_state_receiver,
    )
    .await;

    let bind_address = format!("{}:{}", config.host, config.port);
    tracing::info!(address = %bind_address,"Binding to address");

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(&bind_address).await?;
    tokio::spawn(async move {
        tracing::info!("Handle incoming connections");
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

    tracing::info!(address = %bind_address,"Successfully bound to address");
    Ok(())
}

async fn handle_request(
    req: hyper::Request<Body>,
    state: Arc<WebServerState>,
) -> Result<hyper::Response<Body>, Infallible> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/hello") => Ok(Response::new(Body::from("Hello, world!"))),
        ("GET", "/get_keyshares") => {
            let keyshares = state.export_keyshares_receiver.borrow().clone();
            let json = serde_json::to_string(&keyshares).unwrap_or_else(|_| "invalid".to_string());
            let mut response = Response::new(Body::from(json));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }
        ("PUT", "/set_keyshares") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await;
            match whole_body {
                Ok(bytes) => match serde_json::from_slice::<Vec<Keyshare>>(&bytes) {
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
                        .body(Body::from(format!("Invalid Json: {err}")))
                        .unwrap()),
                },
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
    authenticate_peer(&stream.get_ref().1, &expected_pk)?;
    tracing::info!(
        "TLS handshake complete, backup service authenticated and encrypted channel established."
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
            tracing::info!("dropping connection due to cancellation (change in migration info or cancellatin of web server)");
        }
    }
    anyhow::Ok(())
}
