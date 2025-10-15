use std::{convert::Infallible, sync::Arc};

use super::types::MigrationInfo;
use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use hyper::{
    body::to_bytes, client::conn::SendRequest, service::service_fn, Body, Request, Response,
    StatusCode,
};
use mpc_tls::tls::configure_tls;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{config::WebUIConfig, keyshare::Keyshare};

#[derive(Clone)]
pub struct WebServerState {
    import_keyshares_sender: watch::Sender<Vec<Keyshare>>,
    export_keyshares_receiver: watch::Receiver<Vec<Keyshare>>,
}

#[allow(dead_code)]
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

#[derive(Clone)]
struct ExpectedPeerInfo {
    expected_pk: Option<VerifyingKey>,
    cancelled: CancellationToken,
}

impl ExpectedPeerInfo {
    pub fn from_migration(migration_info: MigrationInfo, cancelled: CancellationToken) -> Self {
        let expected_pk = migration_info.get_pk_backup_service();
        Self {
            expected_pk,
            cancelled,
        }
    }
}

#[allow(dead_code)]
fn authenticate_peer(
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

#[allow(dead_code)]
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

#[allow(dead_code)]
/// Connects to the web server, performs the TLS handshake and sends a simple HTTP request.
pub async fn connect_to_web_server(
    p2p_private_key: &ed25519_dalek::SigningKey,
    target_address: &str,
    expected_server_key: VerifyingKey,
) -> anyhow::Result<SendRequest<Body>> {
    let (_server_config, client_config) = configure_tls(p2p_private_key)?;
    let conn = TcpStream::connect(target_address)
        .await
        .context("TCP connect")?;
    let tls_conn = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect("dummy".try_into().unwrap(), conn)
        .await
        .context("TLS connect")?;

    authenticate_peer(tls_conn.get_ref().1, &expected_server_key)?;

    tracing::info!(
        "TLS handshake complete, backup service authenticated and encrypted channel established."
    );

    let (request_sender, connection) = hyper::client::conn::handshake(tls_conn)
        .await
        .context("failed to perform HTTP handshake")?;

    // Run the connection driver in the background.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::error!("Connection error: {err}");
        }
    });

    Ok(request_sender)
}

/// server matches on path only
const BOGUS_URL: &str = "http://example";
async fn make_hello_request(request_sender: &mut SendRequest<Body>) -> anyhow::Result<String> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("{}/hello", BOGUS_URL))
        .body(hyper::Body::empty())?;

    let response = request_sender.send_request(req).await?;
    let body_bytes = to_bytes(response.into_body()).await?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!("Response: {}", body_str);
    Ok(body_str.to_string())
}

async fn make_keyshare_get_request(
    request_sender: &mut SendRequest<Body>,
) -> anyhow::Result<Vec<Keyshare>> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("{}/get_keyshares", BOGUS_URL))
        .body(hyper::Body::empty())?;

    let response = request_sender.send_request(req).await?;
    // Check HTTP status
    if !response.status().is_success() {
        let status = response.status();
        let body_bytes = to_bytes(response.into_body())
            .await
            .context("failed to read error body")?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        anyhow::bail!("server returned {}: {}", status, body_str);
    }

    // Collect the response body
    let body_bytes = to_bytes(response.into_body())
        .await
        .context("failed to read body")?;

    // Parse JSON into Vec<Keyshare>
    let keyshares: Vec<Keyshare> =
        serde_json::from_slice(&body_bytes).context("failed to parse JSON keyshares")?;

    tracing::debug!("Received keyshares: {:?}", keyshares);

    Ok(keyshares)
}

async fn make_set_keyshares_request(
    request_sender: &mut SendRequest<Body>,
    keyshares: Vec<Keyshare>,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(&keyshares)?;

    let req = Request::builder()
        .method("PUT")
        .uri(format!("{}/set_keyshares", BOGUS_URL))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))?;
    let response = request_sender.send_request(req).await?;

    // Check status code
    if !response.status().is_success() {
        let status = response.status();
        let body_bytes = to_bytes(response.into_body())
            .await
            .context("failed to read error body")?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        anyhow::bail!("server returned {}: {}", status, body_str);
    }

    // Optionally read response body (the server sends "Keyshares received.")
    let body_bytes = to_bytes(response.into_body())
        .await
        .context("failed to read response body")?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!("Server response: {}", body_str);

    Ok(())
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use mpc_contract::node_migrations::BackupServiceInfo;
    use rand::rngs::OsRng;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    use crate::keyshare::test_utils::KeysetBuilder;
    use crate::keyshare::Keyshare;
    use crate::migration_service::web::{
        connect_to_web_server, make_hello_request, make_keyshare_get_request,
        make_set_keyshares_request, start_web_server,
    };
    use crate::{
        config::WebUIConfig, migration_service::types::MigrationInfo, p2p::testing::PortSeed,
    };

    use super::WebServerState;

    const LOCALHOST_IP: &str = "127.0.0.1";

    struct TestSetup {
        client_key: SigningKey,
        server_key: SigningKey,
        target_address: String,
        migration_state_sender: watch::Sender<MigrationInfo>,
        import_keyshares_receiver: watch::Receiver<Vec<Keyshare>>,
        export_keyshares_sender: watch::Sender<Vec<Keyshare>>,
    }

    async fn setup(port_seed: PortSeed) -> TestSetup {
        let client_key = SigningKey::generate(&mut OsRng);
        let server_key = SigningKey::generate(&mut OsRng);

        let port: u16 = port_seed.p2p_port(0);
        let config = WebUIConfig {
            host: LOCALHOST_IP.to_string(),
            port,
        };
        let (migration_state_sender, migration_state_receiver) = watch::channel(MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: client_key.verifying_key().to_bytes().into(),
            }),
            active_migration: false,
        });
        let (import_keyshares_sender, import_keyshares_receiver) = watch::channel(vec![]);
        let (export_keyshares_sender, export_keyshares_receiver) = watch::channel(vec![]);
        let web_server_state = Arc::new(WebServerState {
            import_keyshares_sender,
            export_keyshares_receiver,
        });
        assert!(start_web_server(
            web_server_state.clone(),
            config,
            migration_state_receiver,
            &server_key,
            CancellationToken::new()
        )
        .await
        .is_ok());
        let target_address = format!("{LOCALHOST_IP}:{port}");
        TestSetup {
            client_key,
            server_key,
            target_address,
            migration_state_sender,
            import_keyshares_receiver,
            export_keyshares_sender,
        }
    }

    #[tokio::test]
    async fn test_web_success_hello_world() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_hello_request(&mut send_request).await.unwrap();

        println!("received: {}", res);
        assert_eq!("Hello, world!", res);
    }

    #[tokio::test]
    async fn test_web_failure() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_FAILURE_TEST).await;
        let wrong_backup_service_info = MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: SigningKey::generate(&mut OsRng).to_bytes().into(),
            }),
            active_migration: false,
        };
        test_setup
            .migration_state_sender
            .send(wrong_backup_service_info)
            .unwrap();

        // the handshake will still pass. it is only after we try to send data that we realize the
        // server closed the connection.
        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();

        let res = make_hello_request(&mut send_request).await;
        print!("{:?}", res);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_web_success_get_keyshares() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_keyshare_get_request(&mut send_request).await.unwrap();

        println!("received: {:?}", res);
        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, res);

        let keyset_builder = KeysetBuilder::new_populated(0, 8);
        test_setup
            .export_keyshares_sender
            .send(keyset_builder.keyshares().to_vec())
            .unwrap();
        let res = make_keyshare_get_request(&mut send_request).await.unwrap();
        assert_eq!(keyset_builder.keyshares().to_vec(), res);
    }

    #[tokio::test]
    async fn test_web_success_set_keyshares() {
        let mut test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();

        let received = test_setup
            .import_keyshares_receiver
            .borrow_and_update()
            .clone();
        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, received);

        let keyset_builder = KeysetBuilder::new_populated(0, 8);
        make_set_keyshares_request(&mut send_request, keyset_builder.keyshares().to_vec())
            .await
            .unwrap();

        let received = test_setup
            .import_keyshares_receiver
            .borrow_and_update()
            .clone();
        print!("received: {:?}", received);
        assert_eq!(keyset_builder.keyshares().to_vec(), received);
    }
}
