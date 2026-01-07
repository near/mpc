use super::pprof::collect_pprof;

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{io, net::TcpListener};
use tower::limit::GlobalConcurrencyLimitLayer;

const CONTENT_TYPE_SVG: &str = "image/svg+xml";
const PPROF_FLAMEGRAPH_PATH: &str = "/profiler/pprof/flamegraph";
const MAX_CONCURRENT_PPROF_REQUESTS: usize = 5;

const DEFAULT_PPROF_SAMPLE_DURATION: Duration = Duration::from_secs(30);
const DEFAULT_PPROF_SAMPLE_FREQUENCY_HZ: i32 = 1000;

pub(crate) async fn start_web_server(bind_address: SocketAddr) -> Result<(), io::Error> {
    let pprof_router = axum::Router::new()
        .route(PPROF_FLAMEGRAPH_PATH, axum::routing::get(pprof_flamegraph))
        .layer(GlobalConcurrencyLimitLayer::new(
            MAX_CONCURRENT_PPROF_REQUESTS,
        ));

    let tcp_listener = TcpListener::bind(&bind_address).await?;

    tokio::spawn(async move {
        tracing::info!(?bind_address, "starting profiling server");
        axum::serve(tcp_listener, pprof_router).await
    });

    Ok(())
}

async fn pprof_flamegraph() -> impl IntoResponse {
    let pprof_report = collect_pprof(
        DEFAULT_PPROF_SAMPLE_DURATION,
        DEFAULT_PPROF_SAMPLE_FREQUENCY_HZ,
    )
    .await;

    match pprof_report {
        Ok(report) => {
            let mut svg_buffer = Vec::new();
            let flamegraph_write = report.flamegraph(&mut svg_buffer);
            if let Err(error) = flamegraph_write {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error generating flamegraph: {:#?}", error),
                )
                    .into_response();
            }

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, CONTENT_TYPE_SVG)],
                svg_buffer,
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {:?}", e)).into_response(),
    }
}
