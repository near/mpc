//! Foreign-chain RPC provider health checks: verify each configured provider's chain
//! identity, run the real inspector over a recently produced transaction, and report a
//! per-provider result.

mod checks;
mod golden;
mod network;
mod results;

use std::collections::BTreeMap;
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

use crate::golden::IdentityVector;

/// Config-seeded identity references keyed by chain label, overriding the built-in golden
/// set. Each value is the identity a provider must report for that chain (an EVM or Aptos
/// numeric chain id, a Starknet felt, a Bitcoin genesis hash, a Sui genesis digest). Useful
/// for probing a local or custom network the built-in set doesn't know about.
#[derive(Default)]
pub struct ReferenceOverrides {
    identities: BTreeMap<String, String>,
}

impl ReferenceOverrides {
    pub fn from_identities(identities: BTreeMap<String, String>) -> Self {
        Self { identities }
    }

    fn get(&self, chain: &str) -> Option<&str> {
        self.identities.get(chain).map(String::as_str)
    }
}

/// The config-seeded identity override for `chain`, falling back to the built-in reference.
fn resolve_identity<'a>(
    overrides: &'a ReferenceOverrides,
    chain: &str,
    builtin: Option<IdentityVector>,
) -> Option<&'a str> {
    overrides.get(chain).or(builtin.map(|v| v.identity))
}

/// Probe every configured provider against `network`'s reference values, one
/// [`ProviderResult`] per provider, each checked independently.
/// Chains with no reference for `network`, or configured but unsupported, are
/// [`Status::Skipped`]; a chain absent from the config still yields a single
/// placeholder `Skipped` result so its absence stays visible.
pub async fn check_all_providers(
    fc: &ForeignChainsConfig,
    network: Network,
    overrides: &ReferenceOverrides,
) -> Vec<ProviderResult> {
    let golden = golden::golden_set(network);
    let mut out = Vec::new();

    if let Some(cfg) = &fc.base {
        let expected = resolve_identity(overrides, "base", golden.base);
        run_evm::<Base>("base", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("base", &mut out);
    }
    if let Some(cfg) = &fc.bnb {
        let expected = resolve_identity(overrides, "bnb", golden.bnb);
        run_evm::<Bnb>("bnb", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("bnb", &mut out);
    }
    if let Some(cfg) = &fc.arbitrum {
        let expected = resolve_identity(overrides, "arbitrum", golden.arbitrum);
        run_evm::<Arbitrum>("arbitrum", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("arbitrum", &mut out);
    }
    if let Some(cfg) = &fc.polygon {
        let expected = resolve_identity(overrides, "polygon", golden.polygon);
        run_evm::<Polygon>("polygon", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("polygon", &mut out);
    }
    if let Some(cfg) = &fc.hyper_evm {
        let expected = resolve_identity(overrides, "hyper_evm", golden.hyper_evm);
        run_evm::<HyperEvm>("hyper_evm", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("hyper_evm", &mut out);
    }
    if let Some(cfg) = &fc.abstract_chain {
        let expected = resolve_identity(overrides, "abstract", golden.abstract_chain);
        run_evm::<Abstract>("abstract", cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("abstract", &mut out);
    }
    if let Some(cfg) = &fc.bitcoin {
        let expected = resolve_identity(overrides, "bitcoin", golden.bitcoin);
        run_bitcoin(cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("bitcoin", &mut out);
    }
    if let Some(cfg) = &fc.starknet {
        let expected = resolve_identity(overrides, "starknet", golden.starknet);
        run_starknet(cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("starknet", &mut out);
    }
    if let Some(cfg) = &fc.aptos {
        let expected = resolve_identity(overrides, "aptos", golden.aptos);
        run_aptos(cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("aptos", &mut out);
    }
    if let Some(cfg) = &fc.sui {
        let expected = resolve_identity(overrides, "sui", golden.sui);
        run_sui(cfg, expected, network, &mut out).await;
    } else {
        mark_not_configured("sui", &mut out);
    }

    // Configured but not yet supported by the node (see verify_foreign_tx/sign.rs).
    if let Some(cfg) = &fc.ethereum {
        mark_skipped("ethereum", cfg, "not yet supported by the node", &mut out);
    } else {
        mark_not_configured("ethereum", &mut out);
    }
    if let Some(cfg) = &fc.solana {
        mark_skipped("solana", cfg, "not yet supported by the node", &mut out);
    } else {
        mark_not_configured("solana", &mut out);
    }

    out
}

fn no_reference_reason(network: Network) -> String {
    format!("no {} reference for this chain", network.label())
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
    expected_chain_id: Option<&str>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_skipped(chain, cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_jsonrpc(provider) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok(client) => run_check(timeout, checks::check_evm::<Chain, _>(client, expected)).await,
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
    expected_genesis: Option<&str>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_genesis else {
        mark_skipped("bitcoin", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_jsonrpc(provider) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok(client) => run_check(timeout, checks::check_bitcoin(client, expected)).await,
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
    expected_chain_id: Option<&str>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected_chain_id) = expected_chain_id else {
        mark_skipped("starknet", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_jsonrpc(provider) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok(client) => {
                run_check(timeout, checks::check_starknet(client, expected_chain_id)).await
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
    expected_chain_id: Option<&str>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_skipped("aptos", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_aptos(provider) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok((url, header)) => {
                run_check(timeout, checks::check_aptos(url, header, timeout, expected)).await
            }
        };
        out.push(ProviderResult {
            chain: "aptos",
            provider: provider_name(name),
            status,
        });
    }
}

/// Sui differs from the other probes: its providers prune historical
/// transactions, so there is no long-lived golden transaction to check
/// against. The probe verifies the provider's chain identity instead — see
/// [`checks::check_sui`] for the mechanism.
async fn run_sui(
    cfg: &ForeignChainConfig,
    expected_chain_id: Option<&str>,
    network: Network,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_skipped("sui", cfg, &no_reference_reason(network), out);
        return;
    };
    let timeout = timeout_of(cfg);
    for (name, provider) in cfg.providers.iter() {
        let status = match prepare_sui(provider, timeout) {
            Err(e) => Status::Failed(format!("{e:#}")),
            Ok(client) => run_check(timeout, checks::check_sui(client, expected)).await,
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

/// A chain absent from the config has no providers to enumerate; emit one
/// placeholder [`ProviderResult`] so it still appears in the returned results.
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
        // Given a configured but not-yet-supported chain
        let fc = ForeignChainsConfig {
            ethereum: Some(config_with_provider(AuthConfig::None)),
            ..Default::default()
        };

        // When
        let results =
            check_all_providers(&fc, Network::Mainnet, &ReferenceOverrides::default()).await;

        // Then it is reported skipped as unsupported, not probed
        let ethereum = results
            .iter()
            .find(|r| r.chain == "ethereum")
            .expect("ethereum row");
        assert_matches!(
            &ethereum.status,
            Status::Skipped(reason) if reason.contains("not yet supported")
        );
    }

    #[tokio::test]
    async fn check_all_providers__should_report_every_absent_chain_as_not_configured() {
        // Given nothing configured
        let fc = ForeignChainsConfig::default();

        // When
        let results =
            check_all_providers(&fc, Network::Mainnet, &ReferenceOverrides::default()).await;

        // Then every known chain still appears, each with a "not configured" placeholder
        let expected = [
            "base",
            "bnb",
            "arbitrum",
            "polygon",
            "hyper_evm",
            "abstract",
            "bitcoin",
            "starknet",
            "aptos",
            "sui",
            "ethereum",
            "solana",
        ];
        for chain in expected {
            let row = results
                .iter()
                .find(|r| r.chain == chain)
                .unwrap_or_else(|| panic!("missing row for {chain}"));
            assert_matches!(
                &row.status,
                Status::Skipped(reason) if reason.contains("not configured")
            );
        }
        assert_eq!(results.len(), expected.len());
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
        let results =
            check_all_providers(&fc, Network::Mainnet, &ReferenceOverrides::default()).await;

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
        // Given — one Aptos provider on the expected network with a verifiable recent tx
        // (pass), another on the wrong network (fail), and a separate unsupported chain (skip).
        let healthy = MockServer::start_async().await;
        let broken = MockServer::start_async().await;
        let tx = "aa".repeat(32);
        healthy
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(200)
                    .json_body(serde_json::json!({ "chain_id": 1, "ledger_version": "1000" }));
            })
            .await;
        healthy
            .mock_async(|when, then| {
                when.method(GET).path("/transactions/by_version/900");
                then.status(200)
                    .json_body(aptos_event_body(&tx, "0x1::block::NewBlockEvent", 0));
            })
            .await;
        healthy
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/transactions/by_hash/0x{tx}"));
                then.status(200)
                    .json_body(aptos_event_body(&tx, "0x1::block::NewBlockEvent", 0));
            })
            .await;
        broken
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(200)
                    .json_body(serde_json::json!({ "chain_id": 2, "ledger_version": "1000" }));
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
        let results =
            check_all_providers(&fc, Network::Mainnet, &ReferenceOverrides::default()).await;

        // Then — the broken provider does not suppress the healthy one; pass,
        // fail, and skip all coexist in a single run.
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
