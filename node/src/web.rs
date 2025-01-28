use crate::config::WebUIConfig;
use crate::tracking::TaskHandle;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::serve;
use futures::future::BoxFuture;
use prometheus::{default_registry, Encoder, TextEncoder};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Wrapper to make Axum understand how to convert anyhow::Error into a 500
/// response.
pub(crate) struct AnyhowErrorWrapper(anyhow::Error);

impl From<anyhow::Error> for AnyhowErrorWrapper {
    fn from(e: anyhow::Error) -> Self {
        AnyhowErrorWrapper(e)
    }
}

impl IntoResponse for AnyhowErrorWrapper {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{:?}", self.0)))
            .unwrap()
    }
}

pub(crate) async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[derive(Clone)]
struct WebServerState {
    /// Root task handle for the whole program.
    root_task_handle: Arc<TaskHandle>,
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<crate::tracking::TaskHandle>,
    config: WebUIConfig,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    use futures::FutureExt;

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics))
        .route("/debug/tasks", axum::routing::get(debug_tasks))
        .with_state(WebServerState { root_task_handle });

    let tcp_listener = TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
