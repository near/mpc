use crate::config::SecretsConfig;
use crate::indexer::migrations::ContractMigrationInfo;
use crate::tracking::TaskHandle;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::{serve, Json};
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_attestation::attestation::Attestation;
use mpc_node_config::{
    CKDConfig, ConfigFile, IndexerConfig, KeygenConfig, PresignatureConfig, SignatureConfig,
    TripleConfig,
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_mpc_contract_interface::types::ProtocolContractState;
use node_types::http_server::StaticWebData;
use prometheus::{default_registry, Encoder, TextEncoder};
use serde::Serialize;
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
    node_config: NodeConfigResponse,
}

/// API-safe view of [`ConfigFile`] served by `/debug/node_config`.
///
/// Intentionally decoupled from [`ConfigFile`]: new fields are opt-in, so
/// a field added to [`ConfigFile`] is *not* exposed unless it is also
/// added here. When extending the response, prefer omitting any sub-config
/// that could carry sensitive or operationally significant data (RPC
/// providers, auth credentials, third-party integrations) entirely, rather
/// than mirroring it via "API-safe duplicate" types that strip individual
/// fields — those duplicates require keeping two definitions in sync and
/// a missed update silently leaks data.
#[derive(Clone, Serialize)]
struct NodeConfigResponse {
    my_near_account_id: AccountId,
    near_responder_account_id: AccountId,
    number_of_responder_keys: usize,
    web_ui: SocketAddr,
    migration_web_ui: SocketAddr,
    pprof_bind_address: SocketAddr,
    indexer: IndexerConfig,
    triple: TripleConfig,
    presignature: PresignatureConfig,
    signature: SignatureConfig,
    ckd: CKDConfig,
    keygen: KeygenConfig,
    cores: Option<usize>,
}

impl From<ConfigFile> for NodeConfigResponse {
    fn from(config: ConfigFile) -> Self {
        Self {
            my_near_account_id: config.my_near_account_id,
            near_responder_account_id: config.near_responder_account_id,
            number_of_responder_keys: config.number_of_responder_keys,
            web_ui: config.web_ui,
            migration_web_ui: config.migration_web_ui,
            pprof_bind_address: config.pprof_bind_address,
            indexer: config.indexer,
            triple: config.triple,
            presignature: config.presignature,
            signature: config.signature,
            ckd: config.ckd,
            keygen: config.keygen,
            cores: config.cores,
        }
    }
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    match state.root_task_handle.get() {
        Some(root_task_handle) => format!("{:?}", root_task_handle.report()),
        None => "No root task has started yet.".to_string(),
    }
}

async fn debug_node_config(State(state): State<WebServerState>) -> Json<NodeConfigResponse> {
    Json(state.node_config.clone())
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
    RecentVerifyForeignTxs,
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

    near_mpc_contract_interface::types::protocol_state_to_string(&protocol_state)
}

async fn third_party_licenses() -> Html<&'static str> {
    Html(include_str!("../../../third-party-licenses/licenses.html"))
}

struct PublicKeys {
    near_signer_public_key: Ed25519PublicKey,
    near_p2p_public_key: Ed25519PublicKey,
    near_responder_public_keys: Vec<Ed25519PublicKey>,
}

fn get_public_keys(secrets_config: &SecretsConfig) -> PublicKeys {
    let near_signer_public_key = Ed25519PublicKey::from(
        &secrets_config
            .persistent_secrets
            .near_signer_key
            .verifying_key(),
    );
    let near_p2p_public_key = Ed25519PublicKey::from(
        &secrets_config
            .persistent_secrets
            .p2p_private_key
            .verifying_key(),
    );
    let near_responder_public_keys = secrets_config
        .persistent_secrets
        .near_responder_keys
        .iter()
        .map(|x| Ed25519PublicKey::from(&x.verifying_key()))
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
    config: ConfigFile,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    tracing::info!(?bind_address, "attempting to bind web server to address");

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics))
        .route("/debug/tasks", axum::routing::get(debug_tasks))
        .route("/debug/blocks", axum::routing::get(debug_blocks))
        .route("/debug/signatures", axum::routing::get(debug_signatures))
        .route("/debug/ckds", axum::routing::get(debug_ckds))
        .route("/debug/contract", axum::routing::get(contract_state))
        .route("/debug/migrations", axum::routing::get(migrations))
        .route("/debug/node_config", axum::routing::get(debug_node_config))
        .route("/licenses", axum::routing::get(third_party_licenses))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route("/public_data", axum::routing::get(public_data))
        .with_state(WebServerState {
            root_task_handle,
            debug_request_sender,
            protocol_state_receiver,
            migration_state_receiver,
            static_web_data,
            node_config: NodeConfigResponse::from(config),
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::foreign_chains::{
        ForeignChainConfig, ForeignChainProviderConfig, RpcProviderName,
    };
    use mpc_node_config::{AuthConfig, ForeignChainsConfig, SyncMode, TokenConfig};
    use near_indexer_primitives::types::Finality;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::str::FromStr;

    const PROVIDER_ALCHEMY: &str = "alchemy";
    const PROVIDER_ANKR: &str = "ankr";
    const PROVIDER_BLAST: &str = "blast";
    const PROVIDER_PUBLIC: &str = "public";

    const SOLANA_RPC_URL: &str = "https://solana-mainnet.g.alchemy.com/v2/";
    const BITCOIN_RPC_URL: &str = "https://rpc.ankr.com/btc/{api_key}";
    const ETHEREUM_RPC_URL: &str = "https://eth-mainnet.g.alchemy.com/v2/";
    const ABSTRACT_RPC_URL: &str = "https://api.testnet.abs.xyz";
    const BNB_RPC_URL: &str = "https://bsc-rpc.publicnode.com";
    const BASE_RPC_URL: &str = "https://base.publicnode.com";
    const STARKNET_RPC_URL: &str = "https://starknet-mainnet.blastapi.io/";
    const ARBITRUM_RPC_URL: &str = "https://arbitrum.publicnode.com";
    const HYPER_EVM_RPC_URL: &str = "https://rpc.hyperliquid.xyz/evm";
    const POLYGON_RPC_URL: &str = "https://polygon-bor-rpc.publicnode.com";

    const SOLANA_BEARER_TOKEN: &str = "sk-SUPER-SECRET-KEY";
    const BITCOIN_PATH_TOKEN: &str = "ankr-secret-token";
    const STARKNET_QUERY_TOKEN: &str = "blast-secret";
    const ETHEREUM_TOKEN_ENV_VAR: &str = "ALCHEMY_API_KEY";

    fn test_chain(provider_name: &str, rpc_url: &str, auth: AuthConfig) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                RpcProviderName::from(provider_name.to_string()),
                ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    auth,
                },
            ),
        }
    }

    /// Builds a [`ConfigFile`] with one provider per chain, each exercising a
    /// different [`AuthConfig`] variant. Used to verify that no part of
    /// `foreign_chains` (chain names, provider names, URLs, auth, tokens, or
    /// secret values) ever appears in the serialized debug response.
    fn test_config() -> ConfigFile {
        ConfigFile {
            my_near_account_id: AccountId::from_str("test.near").unwrap(),
            near_responder_account_id: AccountId::from_str("test.near").unwrap(),
            number_of_responder_keys: 1,
            web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080),
            migration_web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8081),
            pprof_bind_address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8082),
            indexer: IndexerConfig {
                concurrency: 1.try_into().unwrap(),
                finality: Finality::Final,
                mpc_contract_id: "mpc.test.near".parse().unwrap(),
                port_override: None,
                sync_mode: SyncMode::Latest,
                validate_genesis: false,
            },
            triple: TripleConfig {
                concurrency: 1,
                desired_triples_to_buffer: 10,
                parallel_triple_generation_stagger_time_sec: 1,
                timeout_sec: 60,
            },
            presignature: PresignatureConfig {
                concurrency: 1,
                desired_presignatures_to_buffer: 5,
                timeout_sec: 60,
            },
            signature: SignatureConfig { timeout_sec: 60 },
            ckd: CKDConfig { timeout_sec: 60 },
            keygen: KeygenConfig { timeout_sec: 60 },
            foreign_chains: ForeignChainsConfig {
                solana: Some(test_chain(
                    PROVIDER_ALCHEMY,
                    SOLANA_RPC_URL,
                    AuthConfig::Header {
                        name: http::HeaderName::from_static("authorization"),
                        scheme: Some("Bearer".to_string()),
                        token: TokenConfig::Val {
                            val: SOLANA_BEARER_TOKEN.to_string(),
                        },
                    },
                )),
                bitcoin: Some(test_chain(
                    PROVIDER_ANKR,
                    BITCOIN_RPC_URL,
                    AuthConfig::Path {
                        placeholder: "{api_key}".to_string(),
                        token: TokenConfig::Val {
                            val: BITCOIN_PATH_TOKEN.to_string(),
                        },
                    },
                )),
                ethereum: Some(test_chain(
                    PROVIDER_ALCHEMY,
                    ETHEREUM_RPC_URL,
                    AuthConfig::Query {
                        name: "api_key".to_string(),
                        token: TokenConfig::Env {
                            env: ETHEREUM_TOKEN_ENV_VAR.to_string(),
                        },
                    },
                )),
                abstract_chain: Some(test_chain(
                    PROVIDER_PUBLIC,
                    ABSTRACT_RPC_URL,
                    AuthConfig::None,
                )),
                bnb: Some(test_chain(PROVIDER_PUBLIC, BNB_RPC_URL, AuthConfig::None)),
                base: Some(test_chain(PROVIDER_PUBLIC, BASE_RPC_URL, AuthConfig::None)),
                starknet: Some(test_chain(
                    PROVIDER_BLAST,
                    STARKNET_RPC_URL,
                    AuthConfig::Query {
                        name: "api_key".to_string(),
                        token: TokenConfig::Val {
                            val: STARKNET_QUERY_TOKEN.to_string(),
                        },
                    },
                )),
                arbitrum: Some(test_chain(
                    PROVIDER_PUBLIC,
                    ARBITRUM_RPC_URL,
                    AuthConfig::None,
                )),
                hyper_evm: Some(test_chain(
                    PROVIDER_PUBLIC,
                    HYPER_EVM_RPC_URL,
                    AuthConfig::None,
                )),
                polygon: Some(test_chain(
                    PROVIDER_PUBLIC,
                    POLYGON_RPC_URL,
                    AuthConfig::None,
                )),
            },
            cores: Some(4),
        }
    }

    #[test]
    fn node_config_response_json__does_not_leak_foreign_chain_info() {
        // Given
        let config = test_config();

        // When
        let json = serde_json::to_string(&NodeConfigResponse::from(config)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Then — the structural invariant: the public debug response must
        // not carry a `foreign_chains` field at all.
        let object = value
            .as_object()
            .expect("response must serialize as a JSON object");
        assert!(
            !object.contains_key("foreign_chains"),
            "response must not contain a `foreign_chains` key, got: {json}"
        );

        // Defense in depth: catch a regression that re-introduces RPC
        // provider data under a different field name. Each needle below is
        // a value present only in the foreign-chain test fixture, so its
        // appearance anywhere in the serialized response is unambiguous
        // evidence of a leak.
        let forbidden = [
            PROVIDER_ALCHEMY,
            PROVIDER_ANKR,
            PROVIDER_BLAST,
            PROVIDER_PUBLIC,
            SOLANA_RPC_URL,
            BITCOIN_RPC_URL,
            ETHEREUM_RPC_URL,
            ABSTRACT_RPC_URL,
            BNB_RPC_URL,
            BASE_RPC_URL,
            STARKNET_RPC_URL,
            ARBITRUM_RPC_URL,
            HYPER_EVM_RPC_URL,
            POLYGON_RPC_URL,
            SOLANA_BEARER_TOKEN,
            BITCOIN_PATH_TOKEN,
            STARKNET_QUERY_TOKEN,
            ETHEREUM_TOKEN_ENV_VAR,
        ];
        for needle in forbidden {
            assert!(
                !json.contains(needle),
                "JSON response must not contain `{needle}`, got: {json}"
            );
        }
    }
}
