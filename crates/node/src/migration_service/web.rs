use std::{convert::Infallible, sync::Arc};

use super::types::MigrationInfo;
use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use hyper::{body::to_bytes, service::service_fn, Body, Request, Response, StatusCode};
use mpc_tls::tls::configure_tls;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use crate::{config::WebUIConfig, migration_service::types::NodeBackupServiceInfo};

#[derive(Clone)]
struct WebServerState {
    migration_state_receiver: watch::Receiver<MigrationInfo>,
}

#[allow(dead_code)]
async fn handle_with_state(
    req: hyper::Request<Body>,
    state: Arc<WebServerState>,
) -> Result<hyper::Response<Body>, Infallible> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/hello") => Ok(Response::new(Body::from("Hello, world!"))),

        ("GET", "/migrations") => Ok(Response::new(Body::from(format!(
            "{:?}",
            state.migration_state_receiver.borrow().clone()
        )))),

        _ => {
            let mut not_found = Response::new(Body::from("Not Found"));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[allow(dead_code)]
fn authenticate_backup_service(
    migration_state_receiver: &watch::Receiver<MigrationInfo>,
    client_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let expected_pk: VerifyingKey = match migration_state_receiver
        .borrow()
        .clone()
        .backup_service_info
    {
        Some(backup_service_info) => {
            let service =
                NodeBackupServiceInfo::from_contract(backup_service_info).context("failed")?;
            service.p2p_key
        }
        None => {
            anyhow::bail!("no backup service registered.");
        }
    };

    if client_public_key != expected_pk {
        tracing::info!(
            ?expected_pk,
            ?client_public_key,
            "closing connection, public key mismatch"
        );
        anyhow::bail!("closing connection, public key mismatch");
    }
    tracing::info!(
        "TLS handshake complete, backup service authenticated and encrypted channel established."
    );
    Ok(())
}

#[allow(dead_code)]
pub async fn start_web_server(
    config: WebUIConfig,
    migration_state_receiver: watch::Receiver<MigrationInfo>,
    p2p_private_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let (server_config, _client_config) = mpc_tls::tls::configure_tls(p2p_private_key)?;

    tracing::info!(
        host = %config.host,
        port = %config.port,
        "Attempting to bind web server to host",
    );

    let state = Arc::new(WebServerState {
        migration_state_receiver: migration_state_receiver.clone(),
    });
    let bind_address = format!("{}:{}", config.host, config.port);

    tracing::info!(address = %bind_address,"Binding to address");

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(&bind_address).await?;
    tokio::spawn(async move {
        tracing::info!("Handle incoming connections");
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let migration_state_receiver_clone = migration_state_receiver.clone();
            let tls_acceptor = tls_acceptor.clone();
            let state_clone = state.clone();
            tokio::spawn(async move {
                tracing::info!("Handle connection");
                let stream = tls_acceptor.accept(tcp_stream).await?;
                let client_public_key = mpc_tls::tls::extract_public_key(stream.get_ref().1)?;
                authenticate_backup_service(&migration_state_receiver_clone, client_public_key)?;
                tracing::info!("TLS handshake complete, backup service authenticated and encrypted channel established.");
                tokio::spawn(async move {
                    if let Err(err) = hyper::server::conn::Http::new()
                        .serve_connection(
                            stream,
                            service_fn(move |req| handle_with_state(req, state_clone.clone())),
                        )
                        .await
                    {
                        tracing::error!("Error serving connection: {err}");
                    }
                });
                anyhow::Ok(())
            });
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
) -> anyhow::Result<String> {
    let (_server_config, client_config) = configure_tls(p2p_private_key)?;
    let conn = TcpStream::connect(target_address)
        .await
        .context("TCP connect")?;
    let tls_conn = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect("dummy".try_into().unwrap(), conn)
        .await
        .context("TLS connect")?;

    let public_key = mpc_tls::tls::extract_public_key(tls_conn.get_ref().1)?;
    if public_key != expected_server_key {
        tracing::info!(
            ?expected_server_key,
            ?public_key,
            "closing connection, public key mismatch"
        );
        anyhow::bail!("closing connection, public key mismatch");
    }

    tracing::info!(
        "TLS handshake complete, backup service authenticated and encrypted channel established."
    );

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_conn)
        .await
        .context("failed to perform HTTP handshake")?;

    // Run the connection driver in the background
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::error!("Connection error: {err}");
        }
    });

    let req = Request::builder()
        .method("GET")
        .uri("https://example/hello") // doesn’t matter, server matches on path only
        .body(hyper::Body::empty())?;

    let response = request_sender.send_request(req).await?;
    let body_bytes = to_bytes(response.into_body()).await?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!("Response: {}", body_str);

    Ok(body_str.to_string())
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use mpc_contract::node_migrations::BackupServiceInfo;
    use rand::rngs::OsRng;
    use tokio::sync::watch;

    use crate::{
        config::WebUIConfig, migration_service::types::MigrationInfo, p2p::testing::PortSeed,
    };

    use super::{connect_to_web_server, start_web_server};

    #[tokio::test]
    pub async fn test_web_success() {
        let client_key = SigningKey::generate(&mut OsRng);
        let server_key = SigningKey::generate(&mut OsRng);

        let ip = "127.0.0.1";
        let port: u16 = PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST.p2p_port(0);
        let config = WebUIConfig {
            host: ip.to_string(),
            port,
        };
        let (_migration_state_sender, migration_state_receiver) = watch::channel(MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: client_key.verifying_key().to_bytes().into(),
            }),
            active_migration: false,
        });
        let expected_servert_key = server_key.verifying_key();
        tokio::spawn(async move {
            if let Err(err) = start_web_server(config, migration_state_receiver, &server_key).await
            {
                panic!("issue: {}", err);
            }
        });

        tokio::time::sleep(Duration::from_secs(2)).await;
        let target_address = format!("127.0.0.1:{port}");
        let res = connect_to_web_server(&client_key, &target_address, expected_servert_key)
            .await
            .unwrap();
        println!("received: {}", res);
        assert_eq!("Hello, world!", res);
    }

    #[tokio::test]
    pub async fn test_web_failure() {
        let client_key = SigningKey::generate(&mut OsRng);
        let server_key = SigningKey::generate(&mut OsRng);

        let ip = "127.0.0.1";
        let port: u16 = PortSeed::MIGRATION_WEBSERVER_FAILURE_TEST.p2p_port(0);
        let config = WebUIConfig {
            host: ip.to_string(),
            port,
        };
        let (_migration_state_sender, migration_state_receiver) = watch::channel(MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: SigningKey::generate(&mut OsRng).to_bytes().into(),
            }),
            active_migration: false,
        });

        let expected_servert_key = server_key.verifying_key();
        tokio::spawn(async move {
            if let Err(err) = start_web_server(config, migration_state_receiver, &server_key).await
            {
                panic!("issue: {}", err);
            }
        });

        tokio::time::sleep(Duration::from_secs(2)).await;
        let target_address = format!("127.0.0.1:{port}");
        assert!(
            connect_to_web_server(&client_key, &target_address, expected_servert_key)
                .await
                .is_err()
        );
    }
}
