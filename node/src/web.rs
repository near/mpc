use crate::config::WebUIConfig;
use crate::tracking::TaskHandle;
use crate::web_common::metrics;
use axum::extract::State;
use axum::serve;
use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::net::TcpListener;

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
