use crate::config::WebUIConfig;
use crate::mpc_client::MpcClient;
use crate::sign_request::SignatureRequest;
use crate::tracking::TaskHandle;
use crate::tracking::{self};
use crate::web_common::{metrics, AnyhowErrorWrapper};
use anyhow::Context;
use axum::extract::{Query, State};
use axum::{routing::get, Router};
use futures::future::BoxFuture;
use futures::FutureExt;
use futures::{stream, StreamExt, TryStreamExt};
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::sha2::{Digest, Sha256};
use k256::Scalar;
use k256::U256;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time;

fn generate_ids(repeat: usize, seed: u64) -> Vec<[u8; 32]> {
    let mut rng: rand_xorshift::XorShiftRng = rand::SeedableRng::seed_from_u64(seed);
    (0..repeat).map(|_| rng.gen::<[u8; 32]>()).collect()
}

async fn debug_index(
    State(state): State<DebugWebServerState>,
    Query(query): Query<DebugIndexRequest>,
) -> Result<(), AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let repeat = query.repeat.unwrap_or(1);
    for id in generate_ids(repeat, query.seed) {
        mpc_client.clone().add_sign_request(&SignatureRequest {
            id,
            msg_hash: sha256hash(query.msg.as_bytes()),
            tweak: query.tweak,
            entropy: query.entropy,
            timestamp_nanosec: 0,
        });
    }
    Ok(())
}

async fn debug_sign(
    State(state): State<DebugWebServerState>,
    Query(query): Query<DebugSignatureRequest>,
) -> Result<axum::Json<Vec<DebugSignatureOutput>>, AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let client = Arc::new(mpc_client);
    let result = state
        .task_handle
        .scope("debug_sign", async move {
            let repeat = query.repeat.unwrap_or(1);
            let ids = generate_ids(repeat, query.seed);
            let timeout = Duration::from_secs(query.timeout.unwrap_or(60));
            let signatures = time::timeout(
                timeout,
                stream::iter(ids.clone())
                    .map(|id| {
                        tracking::spawn(
                            &format!("debug sign #{:?}", id),
                            client.clone().make_signature(id),
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
                    .map(|(s, pk)| DebugSignatureOutput {
                        big_r: format!("{:?}", s.big_r),
                        s: format!("{:?}", s.s),
                        public_key: format!("{:?}", pk),
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
struct DebugIndexRequest {
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    seed: u64,
    msg: String,
    #[serde(default)]
    tweak: Scalar,
    #[serde(default)]
    entropy: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureRequest {
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    seed: u64,
    #[serde(default)]
    parallelism: Option<usize>,
    #[serde(default)]
    timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureOutput {
    big_r: String,
    s: String,
    public_key: String,
}

#[derive(Clone)]
struct DebugWebServerState {
    /// Task handle for the task that runs the web server.
    task_handle: Arc<TaskHandle>,
    /// Root task handle for the whole program.
    root_task_handle: Arc<TaskHandle>,
    /// MPC client, for signing. We take a OnceCell, so that we can start the
    /// web server (for debugging) before the MPC client is ready.
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
}

async fn debug_tasks(State(state): State<DebugWebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

/// This function exposes insecure endpoints. Use it only in testing.
pub async fn start_web_server_testing(
    root_task_handle: Arc<TaskHandle>,
    config: WebUIConfig,
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let router = Router::new().route("/metrics", get(metrics));

    let router = router.route("/debug/tasks", get(debug_tasks));

    let router = if mpc_client.is_some() {
        router
            .route("/debug/index", get(debug_index))
            .route("/debug/sign", get(debug_sign))
    } else {
        router
    };

    let web_server_state = DebugWebServerState {
        task_handle: tracking::current_task(),
        root_task_handle: root_task_handle.clone(),
        mpc_client: mpc_client.clone(),
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
