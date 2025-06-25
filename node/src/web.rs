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
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};

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
    /// Sender for debug requests that need the MPC client to respond.
    signature_debug_request_sender: broadcast::Sender<SignatureDebugRequest>,
    indexer_sleep_time: watch::Receiver<Instant>,
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

#[derive(Clone)]
pub struct SignatureDebugRequest {
    pub kind: SignatureDebugRequestKind,
    responder: mpsc::Sender<String>,
}

impl SignatureDebugRequest {
    pub fn respond(self, response: String) {
        let _ = self.responder.try_send(response);
    }
}

#[derive(Clone)]
pub enum SignatureDebugRequestKind {
    RecentBlocks,
    RecentSignatures,
}

async fn debug_request_from_node(
    State(state): State<WebServerState>,
    request: SignatureDebugRequestKind,
) -> Result<String, AnyhowErrorWrapper> {
    let (sender, mut receiver) = mpsc::channel(1);
    let request = SignatureDebugRequest {
        kind: request,
        responder: sender,
    };
    if state.signature_debug_request_sender.send(request).is_err() {
        return Err(anyhow::anyhow!("Error: node not in the Running state").into());
    }
    let Some(response) = receiver.recv().await else {
        return Err(anyhow::anyhow!("Node dropped the debug request").into());
    };
    Ok(response)
}

async fn debug_blocks(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, SignatureDebugRequestKind::RecentBlocks).await
}

async fn debug_signatures(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, SignatureDebugRequestKind::RecentSignatures).await
}

async fn sleep_time(state: State<WebServerState>) -> String {
    let indexer_sync_time = state.indexer_sleep_time.borrow();
    let now = Instant::now();

    let sync_duration = now.duration_since(*indexer_sync_time);
    let sender_is_alive = state.indexer_sleep_time.has_changed().is_err();

    format!(
        "Indexer has been waiting for sync for: {:#?}\nIndexer is alive: {:?}",
        sync_duration, sender_is_alive
    )
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<crate::tracking::TaskHandle>,
    signature_debug_request_sender: broadcast::Sender<SignatureDebugRequest>,
    config: WebUIConfig,
    indexer_sleep_time: watch::Receiver<Instant>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    use futures::FutureExt;

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics))
        .route("/debug/tasks", axum::routing::get(debug_tasks))
        .route("/debug/blocks", axum::routing::get(debug_blocks))
        .route("/debug/signatures", axum::routing::get(debug_signatures))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route("/sleep_time", axum::routing::get(sleep_time))
        .with_state(WebServerState {
            root_task_handle,
            signature_debug_request_sender,
            indexer_sleep_time,
        });

    let tcp_listener = TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
