//! Foreign-chain RPC provider health checks: probe every configured provider
//! with a fixed golden request and report a per-provider result. Shared by the
//! `foreign-chain-config-tester` operator CLI and the MPC node's startup health
//! check so the two never drift on golden vectors or auth handling.

mod checks;
mod golden;
pub mod network;
pub mod results;

use std::future::Future;
use std::time::Duration;

use foreign_chain_inspector::abstract_chain::inspector::Abstract;
use foreign_chain_inspector::arbitrum::inspector::Arbitrum;
use foreign_chain_inspector::base::inspector::Base;
use foreign_chain_inspector::bnb::inspector::Bnb;
use foreign_chain_inspector::evm::inspector::EvmChain;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvm;
use foreign_chain_inspector::polygon::inspector::Polygon;
use foreign_chain_inspector::{RpcAuthentication, build_http_client};
use foreign_chain_rpc_auth::auth_config_to_rpc_auth;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use http::{HeaderName, HeaderValue};
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};

pub use network::Network;
pub use results::{ProviderResult, Status};

use crate::golden::{AptosVector, BlockHashVector, SuiVector};

/// Probe every configured provider on every configured chain with the golden
/// reference transaction for `network`, returning one [`ProviderResult`] per
/// provider. Each provider is checked independently: one bad provider does not
/// stop the others from being reported. Chains that are configured but not yet
/// supported by the node, or that have no reference transaction for `network`,
/// are reported as [`Status::Skipped`]. An unconfigured sui still yields a
/// placeholder `Skipped` row so its absence is visible in reports.
pub async fn check_all_providers(
    fc: &ForeignChainsConfig,
    network: Network,
) -> Vec<ProviderResult> {
    let golden = golden::golden_set(network);
    let mut out = Vec::new();

    if let Some(cfg) = &fc.base {
        run_evm::<Base>("base", cfg, golden.base, network, &mut out).await;
    }
    if let Some(cfg) = &fc.bnb {
        run_evm::<Bnb>("bnb", cfg, golden.bnb, network, &mut out).await;
    }
    if let Some(cfg) = &fc.arbitrum {
        run_evm::<Arbitrum>("arbitrum", cfg, golden.arbitrum, network, &mut out).await;
    }
    if let Some(cfg) = &fc.polygon {
        run_evm::<Polygon>("polygon", cfg, golden.polygon, network, &mut out).await;
    }
    if let Some(cfg) = &fc.hyper_evm {
        run_evm::<HyperEvm>("hyper_evm", cfg, golden.hyper_evm, network, &mut out).await;
    }
    if let Some(cfg) = &fc.abstract_chain {
        run_evm::<Abstract>("abstract", cfg, golden.abstract_chain, network, &mut out).await;
    }
    if let Some(cfg) = &fc.bitcoin {
        run_bitcoin(cfg, golden.bitcoin, network, &mut out).await;
    }
    if let Some(cfg) = &fc.starknet {
        run_starknet(cfg, golden.starknet, network, &mut out).await;
    }
    if let Some(cfg) = &fc.aptos {
        run_aptos(cfg, golden.aptos, network, &mut out).await;
    }
    if let Some(cfg) = &fc.sui {
        run_sui(cfg, golden.sui, network, &mut out).await;
    } else {
        mark_not_configured("sui", &mut out);
    }

    // Configured but not yet supported by the node.
    if let Some(cfg) = &fc.ethereum {
        mark_skipped("ethereum", cfg, "not yet supported by the node", &mut out);
    }
    if let Some(cfg) = &fc.solana {
        mark_skipped("solana", cfg, "not yet supported by the node", &mut out);
    }

    out
}

fn no_reference_reason(network: Network) -> String {
    format!(
        "no {} reference transaction for this chain",
        network.label()
    )
}

fn timeout_of(cfg: &ForeignChainConfig) -> Duration {
    Duration::from_secs(cfg.timeout_sec.get())
}

fn provider_name(name: &RpcProviderName) -> String {
    name.as_str().to_owned()
}

fn prepare_jsonrpc(provider: &ForeignChainProviderConfig) -> anyhow::Result<HttpClient> {
    let mut url = provider.rpc_url.clone();
    let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    build_http_client(url, auth).map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))
}

fn prepare_aptos(
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<(String, Option<(HeaderName, HeaderValue)>)> {
    let mut url = provider.rpc_url.clone();
    let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    let header = match auth {
        RpcAuthentication::KeyInUrl => None,
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => Some((header_name, header_value)),
    };
    Ok((url, header))
}

async fn run_check(timeout: Duration, fut: impl Future<Output = anyhow::Result<()>>) -> Status {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => Status::Passed,
        Ok(Err(e)) => Status::Failed(format!("{e:#}")),
        Err(_) => Status::Failed(format!("timed out after {}s", timeout.as_secs())),
    }
}

async fn run_evm<Chain: EvmChain + Send + Sync>(
    chain: &'static str,
    cfg: &ForeignChainConfig,
    vector: Option<BlockHashVector>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(vector) = vector else {
        mark_skipped(chain, cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    let parsed =
        golden::hex32(vector.tx).and_then(|tx| golden::hex32(vector.block_hash).map(|bh| (tx, bh)));
    for (name, provider) in cfg.providers.iter() {
        let status = match (&parsed, prepare_jsonrpc(provider)) {
            (Err(e), _) => Status::Failed(format!("invalid golden vector: {e:#}")),
            (Ok(_), Err(e)) => Status::Failed(format!("{e:#}")),
            (Ok((tx, bh)), Ok(client)) => {
                run_check(timeout, checks::check_evm::<Chain>(client, *tx, *bh)).await
            }
        };
        out.push(ProviderResult {
            chain,
            provider: provider_name(name),
            status,
        });
    }
}

async fn run_bitcoin(
    cfg: &ForeignChainConfig,
    vector: Option<BlockHashVector>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(vector) = vector else {
        mark_skipped("bitcoin", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    let parsed =
        golden::hex32(vector.tx).and_then(|tx| golden::hex32(vector.block_hash).map(|bh| (tx, bh)));
    for (name, provider) in cfg.providers.iter() {
        let status = match (&parsed, prepare_jsonrpc(provider)) {
            (Err(e), _) => Status::Failed(format!("invalid golden vector: {e:#}")),
            (Ok(_), Err(e)) => Status::Failed(format!("{e:#}")),
            (Ok((tx, bh)), Ok(client)) => {
                run_check(timeout, checks::check_bitcoin(client, *tx, *bh)).await
            }
        };
        out.push(ProviderResult {
            chain: "bitcoin",
            provider: provider_name(name),
            status,
        });
    }
}

async fn run_starknet(
    cfg: &ForeignChainConfig,
    vector: Option<BlockHashVector>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(vector) = vector else {
        mark_skipped("starknet", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    let parsed = golden::felt32(vector.tx)
        .and_then(|tx| golden::felt32(vector.block_hash).map(|bh| (tx, bh)));
    for (name, provider) in cfg.providers.iter() {
        let status = match (&parsed, prepare_jsonrpc(provider)) {
            (Err(e), _) => Status::Failed(format!("invalid golden vector: {e:#}")),
            (Ok(_), Err(e)) => Status::Failed(format!("{e:#}")),
            (Ok((tx, bh)), Ok(client)) => {
                run_check(timeout, checks::check_starknet(client, *tx, *bh)).await
            }
        };
        out.push(ProviderResult {
            chain: "starknet",
            provider: provider_name(name),
            status,
        });
    }
}

async fn run_aptos(
    cfg: &ForeignChainConfig,
    vector: Option<AptosVector>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(vector) = vector else {
        mark_skipped("aptos", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    let parsed_tx = golden::hex32(vector.tx);
    for (name, provider) in cfg.providers.iter() {
        let status = match (&parsed_tx, prepare_aptos(provider)) {
            (Err(e), _) => Status::Failed(format!("invalid golden vector: {e:#}")),
            (Ok(_), Err(e)) => Status::Failed(format!("{e:#}")),
            (Ok(tx), Ok((url, header))) => {
                run_check(
                    timeout,
                    checks::check_aptos(
                        url,
                        header,
                        timeout,
                        *tx,
                        vector.event_type_tag,
                        vector.event_sequence_number,
                    ),
                )
                .await
            }
        };
        out.push(ProviderResult {
            chain: "aptos",
            provider: provider_name(name),
            status,
        });
    }
}

async fn run_sui(
    cfg: &ForeignChainConfig,
    vector: Option<SuiVector>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(vector) = vector else {
        mark_skipped("sui", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_sui(provider, timeout) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok(client) => run_check(timeout, checks::check_sui(client, vector.chain_id)).await,
        };
        out.push(ProviderResult {
            chain: "sui",
            provider: provider_name(name),
            status,
        });
    }
}

fn prepare_sui(
    provider: &ForeignChainProviderConfig,
    timeout: Duration,
) -> anyhow::Result<GrpcSuiClient> {
    let mut url = provider.rpc_url.clone();
    let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    let header = match auth {
        RpcAuthentication::KeyInUrl => None,
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => Some((header_name, header_value)),
    };
    GrpcSuiClient::new(url, header, timeout)
        .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))
}

fn mark_skipped(
    chain: &'static str,
    cfg: &ForeignChainConfig,
    reason: &str,
    out: &mut Vec<ProviderResult>,
) {
    for name in cfg.providers.keys() {
        out.push(ProviderResult::skipped(chain, provider_name(name), reason));
    }
}

/// A chain absent from the config has no providers to enumerate, so it gets a single
/// placeholder row — this way every supported chain shows up in the report.
fn mark_not_configured(chain: &'static str, out: &mut Vec<ProviderResult>) {
    out.push(ProviderResult::skipped(
        chain,
        "-".to_string(),
        "not configured",
    ));
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use httpmock::prelude::*;
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;

    fn config_with_provider(auth: AuthConfig) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(5).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "only".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: "https://rpc.example.com".to_string(),
                    auth,
                },
            ),
        }
    }

    #[tokio::test]
    async fn check_all_providers__should_skip_configured_but_unsupported_chains() {
        // Given
        let fc = ForeignChainsConfig {
            ethereum: Some(config_with_provider(AuthConfig::None)),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, Network::Mainnet).await;

        // Then — plus the placeholder row for unconfigured sui
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].chain, "sui");
        assert_matches!(results[0].status, Status::Skipped(_));
        assert_eq!(results[1].chain, "ethereum");
        assert_matches!(results[1].status, Status::Skipped(_));
    }

    #[tokio::test]
    async fn check_all_providers__should_report_absent_sui_as_not_configured() {
        // Given — nothing configured
        let fc = ForeignChainsConfig::default();

        // When
        let results = check_all_providers(&fc, Network::Mainnet).await;

        // Then — sui shows up anyway, reported "not configured"
        assert!(results.iter().any(|r| r.chain == "sui"));
        assert!(results.iter().all(|r| matches!(
            &r.status,
            Status::Skipped(reason) if reason.contains("not configured")
        )));
    }

    #[tokio::test]
    async fn check_all_providers__should_fail_provider_when_env_token_is_unset() {
        // Given
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Env {
                env: "DEFINITELY_UNSET_TOKEN_ENV".to_string(),
            },
        };
        let fc = ForeignChainsConfig {
            base: Some(config_with_provider(auth)),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, Network::Mainnet).await;

        // Then
        assert_eq!(results[0].chain, "base");
        let Status::Failed(reason) = &results[0].status else {
            panic!("expected Failed, got a pass/skip");
        };
        assert!(reason.contains("DEFINITELY_UNSET_TOKEN_ENV"));
    }

    fn aptos_event_body(tx: &str, type_tag: &str, sequence_number: u64) -> serde_json::Value {
        serde_json::json!({
            "type": "block_metadata_transaction",
            "hash": format!("0x{tx}"),
            "success": true,
            "events": [{
                "guid": { "creation_number": "0", "account_address": "0x1" },
                "sequence_number": sequence_number.to_string(),
                "type": type_tag,
                "data": { "epoch": "7510" }
            }]
        })
    }

    fn aptos_provider(rpc_url: String) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url,
            auth: AuthConfig::None,
        }
    }

    #[tokio::test]
    async fn check_all_providers__should_report_pass_fail_and_skip_in_one_run() {
        // Given — on the same chain, one Aptos provider serves the golden event
        // (pass) and another serves a wrong event (fail); a separate unsupported
        // chain is skipped. All three are exercised in a single run.
        let healthy = MockServer::start_async().await;
        let broken = MockServer::start_async().await;
        let aptos = golden::golden_set(Network::Mainnet).aptos.unwrap();
        let tx = aptos.tx;
        healthy
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/transactions/by_hash/0x{tx}"));
                then.status(200).json_body(aptos_event_body(
                    tx,
                    aptos.event_type_tag,
                    aptos.event_sequence_number,
                ));
            })
            .await;
        broken
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/transactions/by_hash/0x{tx}"));
                then.status(200).json_body(aptos_event_body(
                    tx,
                    "0xdead::wrong::Event",
                    aptos.event_sequence_number,
                ));
            })
            .await;

        let mut providers = NonEmptyBTreeMap::new(
            "healthy".to_string().into(),
            aptos_provider(healthy.base_url()),
        );
        providers.insert(
            "broken".to_string().into(),
            aptos_provider(broken.base_url()),
        );
        let fc = ForeignChainsConfig {
            aptos: Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(5).unwrap(),
                max_retries: NonZeroU64::new(1).unwrap(),
                providers,
            }),
            ethereum: Some(config_with_provider(AuthConfig::None)),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, Network::Mainnet).await;

        // Then — the broken provider does not stop the healthy one from being
        // reported, the unsupported chain is skipped, and unconfigured sui
        // gets its placeholder row.
        assert_eq!(results.len(), 4);
        let status = |chain: &str, provider: &str| {
            results
                .iter()
                .find(|r| r.chain == chain && r.provider == provider)
                .map(|r| &r.status)
                .unwrap_or_else(|| panic!("missing result for {chain}/{provider}"))
        };
        assert_matches!(status("aptos", "healthy"), Status::Passed);
        assert_matches!(status("aptos", "broken"), Status::Failed(_));
        assert_matches!(status("ethereum", "only"), Status::Skipped(_));
    }
}
