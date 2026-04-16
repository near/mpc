mod handlers;
mod pccs;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use clap::Parser;
use reqwest::Client;
use tokio::signal;

use crate::pccs::PccsClient;

const PCCS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1MB

/// Local PCCS proxy — Phala-compatible collateral endpoint backed by Intel PCCS.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address and port to listen on.
    #[arg(long, default_value = "0.0.0.0:8082")]
    listen: SocketAddr,

    /// URL of the local Intel PCCS.
    #[arg(long, default_value = "https://localhost:8081")]
    pccs_url: reqwest::Url,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pccs_proxy=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    // TODO(#2928): make TLS verification configurable via CLI flag (e.g. --pccs-tls-insecure).
    // Currently disabled because Intel PCCS typically uses a self-signed certificate.
    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(PCCS_REQUEST_TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(PccsClient {
        pccs_base_url: args.pccs_url.clone(),
        http,
    });

    if state.check_pccs_reachable().await {
        tracing::info!("PCCS is reachable");
    } else {
        tracing::warn!(pccs = %args.pccs_url, "PCCS is not reachable at startup — requests will fail until PCCS becomes available");
    }

    let app = Router::new()
        .route(
            "/api/v1/attestations/verify",
            post(handlers::verify_attestation),
        )
        .route("/health", get(handlers::health))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
        .with_state(state);

    tracing::info!(
        addr = %args.listen,
        pccs = %args.pccs_url,
        "Starting local PCCS proxy"
    );

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .expect("Failed to bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

    tracing::info!("Shutdown complete");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        () = ctrl_c => tracing::info!("Received Ctrl+C, shutting down"),
        () = terminate => tracing::info!("Received SIGTERM, shutting down"),
    }
}
