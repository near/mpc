//! Foreign-chain RPC provider health checks: verify each configured provider's chain
//! identity against the configured expected value, run the real inspector over a recently
//! produced transaction, and report a per-provider result.

mod checks;
mod parse;
mod results;

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

pub use mpc_node_config::ExpectedIdentities;
pub use results::{ProviderResult, Status};

/// Probe every configured provider against its configured expected identity, one
/// [`ProviderResult`] per provider, each checked independently.
/// Configured but unsupported chains are [`Status::Skipped`]; a chain absent from the
/// config still yields a single placeholder `Skipped` result so its absence stays visible.
pub async fn check_all_providers(
    fc: &ForeignChainsConfig,
    identities: &ExpectedIdentities,
) -> Vec<ProviderResult> {
    let mut out = Vec::new();

    if let Some(cfg) = &fc.base {
        run_evm::<Base>("base", cfg, identities.base.as_deref(), &mut out).await;
    } else {
        mark_not_configured("base", &mut out);
    }
    if let Some(cfg) = &fc.bnb {
        run_evm::<Bnb>("bnb", cfg, identities.bnb.as_deref(), &mut out).await;
    } else {
        mark_not_configured("bnb", &mut out);
    }
    if let Some(cfg) = &fc.arbitrum {
        run_evm::<Arbitrum>("arbitrum", cfg, identities.arbitrum.as_deref(), &mut out).await;
    } else {
        mark_not_configured("arbitrum", &mut out);
    }
    if let Some(cfg) = &fc.polygon {
        run_evm::<Polygon>("polygon", cfg, identities.polygon.as_deref(), &mut out).await;
    } else {
        mark_not_configured("polygon", &mut out);
    }
    if let Some(cfg) = &fc.hyper_evm {
        run_evm::<HyperEvm>("hyper_evm", cfg, identities.hyper_evm.as_deref(), &mut out).await;
    } else {
        mark_not_configured("hyper_evm", &mut out);
    }
    if let Some(cfg) = &fc.abstract_chain {
        run_evm::<Abstract>(
            "abstract",
            cfg,
            identities.abstract_chain.as_deref(),
            &mut out,
        )
        .await;
    } else {
        mark_not_configured("abstract", &mut out);
    }
    if let Some(cfg) = &fc.bitcoin {
        run_bitcoin(cfg, identities.bitcoin.as_deref(), &mut out).await;
    } else {
        mark_not_configured("bitcoin", &mut out);
    }
    if let Some(cfg) = &fc.starknet {
        run_starknet(cfg, identities.starknet.as_deref(), &mut out).await;
    } else {
        mark_not_configured("starknet", &mut out);
    }
    if let Some(cfg) = &fc.aptos {
        run_aptos(cfg, identities.aptos.as_deref(), &mut out).await;
    } else {
        mark_not_configured("aptos", &mut out);
    }
    if let Some(cfg) = &fc.sui {
        run_sui(cfg, identities.sui.as_deref(), &mut out).await;
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
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_missing_identity(chain, cfg, out);
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
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_genesis else {
        mark_missing_identity("bitcoin", cfg, out);
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
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected_chain_id) = expected_chain_id else {
        mark_missing_identity("starknet", cfg, out);
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
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_missing_identity("aptos", cfg, out);
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

async fn run_sui(
    cfg: &ForeignChainConfig,
    expected_chain_id: Option<&str>,
    out: &mut Vec<ProviderResult>,
) {
    let Some(expected) = expected_chain_id else {
        mark_missing_identity("sui", cfg, out);
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

/// A configured identity-probed chain without an expected identity is a config error:
/// every provider row fails until `foreign_chain_health_check.identities.<chain>` is set.
fn mark_missing_identity(
    chain: &'static str,
    cfg: &ForeignChainConfig,
    out: &mut Vec<ProviderResult>,
) {
    for name in cfg.providers.keys() {
        out.push(ProviderResult {
            chain,
            provider: provider_name(name),
            status: Status::Failed(format!(
                "no expected identity configured: set foreign_chain_health_check.identities.{chain}"
            )),
        });
    }
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
    async fn check_all_providers__should_fail_identity_chain_without_configured_identity() {
        // Given a configured identity-probed chain but no expected identity in config
        let fc = ForeignChainsConfig {
            starknet: Some(config_with_provider(AuthConfig::None)),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, &ExpectedIdentities::default()).await;

        // Then the provider fails with a pointer to the config key, without being probed
        let starknet = results
            .iter()
            .find(|r| r.chain == "starknet")
            .expect("starknet row");
        assert_matches!(
            &starknet.status,
            Status::Failed(reason)
                if reason.contains("foreign_chain_health_check.identities.starknet")
        );
    }

    #[tokio::test]
    async fn check_all_providers__should_skip_configured_but_unsupported_chains() {
        // Given a configured but not-yet-supported chain
        let fc = ForeignChainsConfig {
            ethereum: Some(config_with_provider(AuthConfig::None)),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, &ExpectedIdentities::default()).await;

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
        let results = check_all_providers(&fc, &ExpectedIdentities::default()).await;

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
        let identities = ExpectedIdentities {
            base: Some("8453".to_string()),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, &identities).await;

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

        let identities = ExpectedIdentities {
            aptos: Some("1".to_string()),
            ..Default::default()
        };

        // When
        let results = check_all_providers(&fc, &identities).await;

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
