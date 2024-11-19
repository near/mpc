use crate::config::WebUIConfig;
use crate::mpc_client::MpcClient;
use crate::tracking::{self, TaskHandle};
use actix_web::error::ErrorInternalServerError;
use actix_web::{get, web};
use futures::{stream, StreamExt, TryStreamExt};
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::sha2::{Digest, Sha256};
use k256::{Scalar, U256};
use prometheus::{default_registry, Encoder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[get("/metrics")]
async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = prometheus::TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[get("/debug/tasks")]
async fn debug_tasks(root_task_handle: web::Data<Arc<TaskHandle>>) -> String {
    format!("{:?}", root_task_handle.report())
}

#[get("/debug/sign")]
async fn debug_sign(
    query: web::Query<DebugSignatureRequest>,
    task_handle: web::Data<Arc<TaskHandle>>,
    mpc_client: web::Data<MpcClient>,
) -> Result<web::Json<Vec<DebugSignatureOutput>>, actix_web::Error> {
    task_handle
        .scope("debug_sign", async move {
            let msg_hash = sha256hash(query.msg.as_bytes());
            let repeat = query.repeat.unwrap_or(1);
            let signatures = stream::iter(0..repeat)
                .map(|_| async {
                    let signature = tracking::spawn(
                        "debug sign repeat",
                        (**mpc_client).clone().make_signature(msg_hash),
                    )
                    .await??;
                    anyhow::Ok(signature)
                })
                .buffered(query.parallelism.unwrap_or(repeat))
                .try_collect::<Vec<_>>()
                .await?;
            anyhow::Ok(web::Json(
                signatures
                    .into_iter()
                    .map(|s| DebugSignatureOutput {
                        big_r: format!("{:?}", s.big_r),
                        s: format!("{:?}", s.s),
                    })
                    .collect(),
            ))
        })
        .await
        .map_err(ErrorInternalServerError)
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
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    parallelism: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureOutput {
    big_r: String,
    s: String,
}

pub async fn run_web_server(
    root_task_handle: Arc<TaskHandle>,
    config: WebUIConfig,
    mpc_client: MpcClient,
) -> anyhow::Result<()> {
    let task_handle = tracking::current_task();
    let server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(web::Data::new(task_handle.clone()))
            .app_data(web::Data::new(root_task_handle.clone()))
            .app_data(web::Data::new(mpc_client.clone()))
            .service(metrics)
            .service(debug_tasks)
            .service(debug_sign)
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run();
    server.await?;
    Ok(())
}
