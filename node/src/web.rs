use crate::config::WebUIConfig;
use crate::mpc_client::MpcClient;
use crate::tracking::{self, TaskHandle};
use anyhow::Context;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use futures::future::BoxFuture;
use futures::{stream, FutureExt, StreamExt, TryStreamExt};
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::sha2::{Digest, Sha256};
use k256::{Scalar, U256};
use prometheus::{default_registry, Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time;

struct AnyhowErrorWrapper(anyhow::Error);

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

async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

async fn debug_sign(
    State(state): State<WebServerState>,
    Query(query): Query<DebugSignatureRequest>,
) -> Result<axum::Json<Vec<DebugSignatureOutput>>, AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let result = state
        .task_handle
        .scope("debug_sign", async move {
            let msg_hash = sha256hash(query.msg.as_bytes());
            let repeat = query.repeat.unwrap_or(1);
            let timeout = Duration::from_secs(query.timeout.unwrap_or(60));

            let signatures = time::timeout(
                timeout,
                stream::iter(0..repeat)
                    .map(|i| {
                        tracking::spawn(
                            &format!("debug sign #{}", i),
                            mpc_client.clone().make_signature(
                                msg_hash,
                                query.tweak,
                                query.entropy,
                            ),
                        )
                        .map(|result| anyhow::Ok(result??))
                    })
                    .buffered(query.parallelism.unwrap_or(repeat))
                    .try_collect::<Vec<_>>(),
            )
            .await
            .context("timeout")?
            .context("signature failed")?;

            anyhow::Ok(axum::Json(
                signatures
                    .into_iter()
                    .map(|s| DebugSignatureOutput {
                        big_r: format!("{:?}", s.big_r),
                        s: format!("{:?}", s.s),
                    })
                    .collect(),
            ))
        })
        .await?;
    Ok(result)
}

fn sha256hash(data: &[u8]) -> k256::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_uint_unchecked(U256::from_be_slice(&bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureRequest {
    msg: String,
    tweak: Scalar,
    entropy: [u8; 32],
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    parallelism: Option<usize>,
    #[serde(default)]
    timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureOutput {
    big_r: String,
    s: String,
}

#[derive(Clone)]
struct WebServerState {
    /// Task handle for the task that runs the web server.
    task_handle: Arc<TaskHandle>,
    /// Root task handle for the whole program.
    root_task_handle: Arc<TaskHandle>,
    /// MPC client, for signing. We take a OnceCell, so that we can start the
    /// web server (for debugging) before the MPC client is ready.
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<TaskHandle>,
    config: WebUIConfig,
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let web_server_state = WebServerState {
        task_handle: tracking::current_task(),
        root_task_handle,
        mpc_client: mpc_client.clone(),
    };

    let router = Router::new()
        .route("/metrics", get(metrics))
        .route("/debug/tasks", get(debug_tasks));
    let router = if mpc_client.is_some() {
        router.route("/debug/sign", get(debug_sign))
    } else {
        router
    };
    let router = router.with_state(web_server_state);

    let tcp_listener =
        tokio::net::TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        axum::serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
