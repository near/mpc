use super::pprof::collect_pprof;

use axum::{
    extract::Query,
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
const MIN_PPROF_SAMPLE_DURATION: Duration = Duration::from_secs(1);
const MAX_PPROF_SAMPLE_DURATION: Duration = Duration::from_secs(180); // 3 minutes

const DEFAULT_PPROF_SAMPLE_FREQUENCY_HZ: i32 = 1000;
const MIN_PPROF_SAMPLE_FREQUENCY_HZ: i32 = 100;
const MAX_PPROF_SAMPLE_FREQUENCY_HZ: i32 = 2000;

pub(crate) async fn start_web_server(bind_address: SocketAddr) -> Result<(), io::Error> {
    let pprof_router = axum::Router::new()
        .route(PPROF_FLAMEGRAPH_PATH, axum::routing::get(pprof_flamegraph))
        .layer(GlobalConcurrencyLimitLayer::new(
            MAX_CONCURRENT_PPROF_REQUESTS,
        ));

    let tcp_listener = TcpListener::bind(&bind_address).await?;

    tokio::spawn(async move {
        tracing::info!(?bind_address, "starting profiling server");
        if let Err(err) = axum::serve(tcp_listener, pprof_router).await {
            tracing::error!(?err, "profiling server failed");
        }
    });

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct PprofParameters {
    sampling_duration_secs: Option<u64>,
    sampling_frequency_hz: Option<i32>,
}

async fn pprof_flamegraph(Query(params): Query<PprofParameters>) -> impl IntoResponse {
    let sample_duration = params
        .sampling_duration_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PPROF_SAMPLE_DURATION)
        .clamp(MIN_PPROF_SAMPLE_DURATION, MAX_PPROF_SAMPLE_DURATION);

    let sample_frequency = params
        .sampling_frequency_hz
        .unwrap_or(DEFAULT_PPROF_SAMPLE_FREQUENCY_HZ)
        .clamp(MIN_PPROF_SAMPLE_FREQUENCY_HZ, MAX_PPROF_SAMPLE_FREQUENCY_HZ);

    let pprof_report = collect_pprof(sample_duration, sample_frequency).await;

    match pprof_report {
        Ok(report) => {
            let mut svg_buffer = Vec::new();
            let flamegraph_write = report.flamegraph(&mut svg_buffer);
            if let Err(error) = flamegraph_write {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error generating flamegraph: {error:#?}"),
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {e:?}")).into_response(),
    }
}
