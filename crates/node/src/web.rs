use crate::config::SecretsConfig;
use crate::indexer::migrations::ContractMigrationInfo;
use crate::tracking::TaskHandle;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::{serve, Json};
use ed25519_dalek::VerifyingKey;
use futures::future::BoxFuture;
use mpc_attestation::attestation::Attestation;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::utils::protocol_state_to_string;
use node_types::http_server::StaticWebData;
use prometheus::{default_registry, Encoder, TextEncoder};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
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
    // Ensure build info metric is always set before gathering metrics
    crate::metrics::init_build_info_metric();

    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[derive(Clone)]
struct WebServerState {
    /// Root task handle for the whole program.
    root_task_handle: Arc<OnceLock<Arc<TaskHandle>>>,
    /// Sender for debug requests that need the MPC client to respond.
    debug_request_sender: broadcast::Sender<DebugRequest>,
    /// Receiver for contract state
    protocol_state_receiver: watch::Receiver<ProtocolContractState>,
    migration_state_receiver: watch::Receiver<(u64, ContractMigrationInfo)>,
    static_web_data: StaticWebData,
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    match state.root_task_handle.get() {
        Some(root_task_handle) => format!("{:?}", root_task_handle.report()),
        None => "No root task has started yet.".to_string(),
    }
}

#[derive(Clone)]
pub struct DebugRequest {
    pub kind: DebugRequestKind,
    responder: mpsc::Sender<String>,
}

impl DebugRequest {
    pub fn respond(self, response: String) {
        let _ = self.responder.try_send(response);
    }
}

#[derive(Clone)]
pub enum DebugRequestKind {
    RecentBlocks,
    RecentSignatures,
    RecentCKDs,
}

async fn debug_request_from_node(
    State(state): State<WebServerState>,
    request: DebugRequestKind,
) -> Result<String, AnyhowErrorWrapper> {
    let (sender, mut receiver) = mpsc::channel(1);
    let request = DebugRequest {
        kind: request,
        responder: sender,
    };
    if state.debug_request_sender.send(request).is_err() {
        return Err(anyhow::anyhow!("Error: node not in the Running state").into());
    }
    let Some(response) = receiver.recv().await else {
        return Err(anyhow::anyhow!("Node dropped the debug request").into());
    };
    Ok(response)
}

async fn debug_blocks(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, DebugRequestKind::RecentBlocks).await
}

async fn debug_signatures(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, DebugRequestKind::RecentSignatures).await
}

async fn debug_ckds(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, DebugRequestKind::RecentCKDs).await
}

async fn migrations(state: State<WebServerState>) -> Json<(u64, ContractMigrationInfo)> {
    Json(state.migration_state_receiver.borrow().clone())
}

async fn contract_state(state: State<WebServerState>) -> String {
    let protocol_state = state
        .protocol_state_receiver
        .borrow()
        // Clone to avoid holding a lock
        .clone();

    protocol_state_to_string(&protocol_state)
}

async fn third_party_licenses() -> Html<&'static str> {
    Html(include_str!("../../../third-party-licenses/licenses.html"))
}

struct PublicKeys {
    near_signer_public_key: VerifyingKey,
    near_p2p_public_key: VerifyingKey,
    near_responder_public_keys: Vec<VerifyingKey>,
}

fn get_public_keys(secrets_config: &SecretsConfig) -> PublicKeys {
    let near_signer_public_key = secrets_config
        .persistent_secrets
        .near_signer_key
        .verifying_key();
    let near_p2p_public_key = secrets_config
        .persistent_secrets
        .p2p_private_key
        .verifying_key();
    let near_responder_public_keys = secrets_config
        .persistent_secrets
        .near_responder_keys
        .iter()
        .map(|x| x.verifying_key())
        .collect();

    PublicKeys {
        near_signer_public_key,
        near_p2p_public_key,
        near_responder_public_keys,
    }
}

pub fn static_web_data(
    value: &SecretsConfig,
    tee_participant_info: Option<Attestation>,
) -> StaticWebData {
    let public_keys = get_public_keys(value);

    StaticWebData {
        near_signer_public_key: public_keys.near_signer_public_key,
        near_p2p_public_key: public_keys.near_p2p_public_key,
        near_responder_public_keys: public_keys.near_responder_public_keys,
        tee_participant_info,
    }
}

async fn public_data(state: State<WebServerState>) -> Json<StaticWebData> {
    state.static_web_data.clone().into()
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<OnceLock<Arc<TaskHandle>>>,
    debug_request_sender: broadcast::Sender<DebugRequest>,
    bind_address: SocketAddr,
    static_web_data: StaticWebData,
    protocol_state_receiver: watch::Receiver<ProtocolContractState>,
    migration_state_receiver: watch::Receiver<(u64, ContractMigrationInfo)>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    use futures::FutureExt;

    tracing::info!(?bind_address, "attempting to bind web server to address");

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics))
        .route("/debug/tasks", axum::routing::get(debug_tasks))
        .route("/debug/blocks", axum::routing::get(debug_blocks))
        .route("/debug/signatures", axum::routing::get(debug_signatures))
        .route("/debug/ckds", axum::routing::get(debug_ckds))
        .route("/debug/contract", axum::routing::get(contract_state))
        .route("/debug/migrations", axum::routing::get(migrations))
        .route("/licenses", axum::routing::get(third_party_licenses))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route("/public_data", axum::routing::get(public_data))
        .with_state(WebServerState {
            root_task_handle,
            debug_request_sender,
            protocol_state_receiver,
            migration_state_receiver,
            static_web_data,
        });

    let tcp_listener = TcpListener::bind(&bind_address).await?;

    tracing::info!(address = %bind_address,"Successfully bound to address");

    Ok(async move {
        tracing::info!("Starting to serve requests...");
        serve(tcp_listener, router).await?;
        tracing::info!("Server stopped successfully.");
        anyhow::Ok(())
    }
    .boxed())
}
