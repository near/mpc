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
use mpc_node_config::foreign_chains::{ForeignChainConfig, ForeignChainProviderConfig};
use mpc_node_config::{
    CKDConfig, ConfigFile, ForeignChainsConfig, IndexerConfig, KeygenConfig, PresignatureConfig,
    RpcProvider, SignatureConfig, TripleConfig,
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_mpc_contract_interface::types::ProtocolContractState;
use node_types::http_server::StaticWebData;
use prometheus::{default_registry, Encoder, TextEncoder};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::NonZeroU64;
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

/// Safe duplicate of ConfigFile for the debug endpoint.
/// This struct is intentionally decoupled from ConfigFile so that if secret
/// fields are added to ConfigFile in the future, they won't be leaked via
/// the API. When adding new fields to ConfigFile, only add them here if they
/// are safe to expose.
/// Moreover, to decouple internal structure from what's served in the API.
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
    foreign_chains: ForeignChains,
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
            foreign_chains: config.foreign_chains.into(),
            cores: config.cores,
        }
    }
}

// ---------------------------------------------------------------------------
// API-safe duplicates of foreign-chain config types.
// These deliberately omit sensitive fields (auth tokens, credentials) so they
// can never be leaked through the debug endpoint.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ForeignChains {
    #[serde(skip_serializing_if = "Option::is_none")]
    solana: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitcoin: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ethereum: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    abstract_chain: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    starknet: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bnb: Option<ForeignChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<ForeignChain>,
}

impl From<ForeignChainsConfig> for ForeignChains {
    fn from(config: ForeignChainsConfig) -> Self {
        Self {
            solana: config.solana.map(Into::into),
            bitcoin: config.bitcoin.map(Into::into),
            ethereum: config.ethereum.map(Into::into),
            abstract_chain: config.abstract_chain.map(Into::into),
            starknet: config.starknet.map(Into::into),
            bnb: config.bnb.map(Into::into),
            base: config.base.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ForeignChain {
    timeout_sec: NonZeroU64,
    max_retries: NonZeroU64,
    providers: BTreeMap<String, ForeignChainProvider>,
}

impl From<ForeignChainConfig> for ForeignChain {
    fn from(config: ForeignChainConfig) -> Self {
        let providers: BTreeMap<String, ForeignChainProviderConfig> = config.providers.into();
        Self {
            timeout_sec: config.timeout_sec,
            max_retries: config.max_retries,
            providers: providers.into_iter().map(|(k, v)| (k, v.into())).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ForeignChainProvider {
    rpc_url: String,
    api_variant: RpcProvider,
}

impl From<ForeignChainProviderConfig> for ForeignChainProvider {
    fn from(provider: ForeignChainProviderConfig) -> Self {
        Self {
            rpc_url: provider.rpc_url,
            api_variant: provider.api_variant,
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

    // TODO(#2880): share `protocol_state_to_string` with the contract crate.
    format!("{:#?}", protocol_state)
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
    use mpc_node_config::{AuthConfig, SyncMode, TokenConfig};
    use near_indexer_primitives::types::Finality;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn test_chain(
        provider_name: &str,
        rpc_url: &str,
        api_variant: RpcProvider,
        auth: AuthConfig,
    ) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                provider_name.to_string(),
                ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    api_variant,
                    auth,
                },
            ),
        }
    }

    /// Builds a [`ConfigFile`] with one provider per chain, each exercising a
    /// different [`AuthConfig`] variant so every conversion path is covered.
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
                    "alchemy",
                    "https://solana-mainnet.g.alchemy.com/v2/",
                    RpcProvider::Alchemy,
                    AuthConfig::Header {
                        name: http::HeaderName::from_static("authorization"),
                        scheme: Some("Bearer".to_string()),
                        token: TokenConfig::Val {
                            val: "sk-SUPER-SECRET-KEY".to_string(),
                        },
                    },
                )),
                bitcoin: Some(test_chain(
                    "ankr",
                    "https://rpc.ankr.com/btc/{api_key}",
                    RpcProvider::Standard,
                    AuthConfig::Path {
                        placeholder: "{api_key}".to_string(),
                        token: TokenConfig::Val {
                            val: "ankr-secret-token".to_string(),
                        },
                    },
                )),
                ethereum: Some(test_chain(
                    "alchemy",
                    "https://eth-mainnet.g.alchemy.com/v2/",
                    RpcProvider::Alchemy,
                    AuthConfig::Query {
                        name: "api_key".to_string(),
                        token: TokenConfig::Env {
                            env: "ALCHEMY_API_KEY".to_string(),
                        },
                    },
                )),
                abstract_chain: Some(test_chain(
                    "public",
                    "https://api.testnet.abs.xyz",
                    RpcProvider::Standard,
                    AuthConfig::None,
                )),
                bnb: Some(test_chain(
                    "public",
                    "https://bsc-rpc.publicnode.com",
                    RpcProvider::Standard,
                    AuthConfig::None,
                )),
                base: Some(test_chain(
                    "public",
                    "https://base.publicnode.com",
                    RpcProvider::Standard,
                    AuthConfig::None,
                )),
                starknet: Some(test_chain(
                    "blast",
                    "https://starknet-mainnet.blastapi.io/",
                    RpcProvider::Blast,
                    AuthConfig::Query {
                        name: "api_key".to_string(),
                        token: TokenConfig::Val {
                            val: "blast-secret".to_string(),
                        },
                    },
                )),
            },
            cores: Some(4),
        }
    }

    #[test]
    fn node_config_response_from__omits_auth_from_solana_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.solana.unwrap().providers["alchemy"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://solana-mainnet.g.alchemy.com/v2/".to_string(),
                api_variant: RpcProvider::Alchemy,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_bitcoin_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.bitcoin.unwrap().providers["ankr"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://rpc.ankr.com/btc/{api_key}".to_string(),
                api_variant: RpcProvider::Standard,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_ethereum_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.ethereum.unwrap().providers["alchemy"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://eth-mainnet.g.alchemy.com/v2/".to_string(),
                api_variant: RpcProvider::Alchemy,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_abstract_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.abstract_chain.unwrap().providers["public"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://api.testnet.abs.xyz".to_string(),
                api_variant: RpcProvider::Standard,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_starknet_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.starknet.unwrap().providers["blast"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://starknet-mainnet.blastapi.io/".to_string(),
                api_variant: RpcProvider::Blast,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_bnb_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.bnb.unwrap().providers["public"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://bsc-rpc.publicnode.com".to_string(),
                api_variant: RpcProvider::Standard,
            }
        );
    }

    #[test]
    fn node_config_response_from__omits_auth_from_base_provider() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let provider = &response.foreign_chains.base.unwrap().providers["public"];
        assert_eq!(
            *provider,
            ForeignChainProvider {
                rpc_url: "https://base.publicnode.com".to_string(),
                api_variant: RpcProvider::Standard,
            }
        );
    }

    #[test]
    fn node_config_response_from__preserves_chain_level_fields() {
        // Given
        let config = test_config();

        // When
        let response = NodeConfigResponse::from(config);

        // Then
        let solana = response.foreign_chains.solana.unwrap();
        assert_eq!(solana.timeout_sec.get(), 30);
        assert_eq!(solana.max_retries.get(), 3);
    }

    #[test]
    fn node_config_response_json__does_not_contain_auth() {
        // Given
        let config = test_config();

        // When
        let json = serde_json::to_string(&NodeConfigResponse::from(config)).unwrap();

        // Then
        assert!(
            !json.contains("auth"),
            "JSON response must not contain auth fields, got: {json}"
        );
        assert!(
            !json.contains("token"),
            "JSON response must not contain token fields, got: {json}"
        );
        assert!(
            !json.contains("sk-SUPER-SECRET-KEY"),
            "JSON response must not contain secret values"
        );
        assert!(
            !json.contains("ankr-secret-token"),
            "JSON response must not contain secret values"
        );
        assert!(
            !json.contains("blast-secret"),
            "JSON response must not contain secret values"
        );
    }
}
