//! Log-only startup check that every configured foreign-chain RPC provider serves the
//! network the operator expects (`expected_chain_id` in the chain's config).
//!
//! A provider pointed at the wrong network (right chain, wrong network — e.g. Sepolia
//! instead of mainnet) answers RPCs normally, so nothing fails until a real verification
//! request arrives. At that point the misconfigured provider disagrees with its healthy
//! siblings and [`foreign_chain_inspector::FanOut`] rejects the whole chain with
//! [`ForeignChainInspectionError::InspectorResponseMismatch`] — an outage, not a warning.
//! This check surfaces the misconfiguration at boot instead, naming the provider.

use std::time::Duration;

use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::{ChainIdentity, FanOut, ForeignChainInspectionError};
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{ForeignChainConfig, ForeignChainsConfig};
use near_mpc_contract_interface::types as dtos;

use crate::providers::verify_foreign_tx::ForeignChainInspectors;

/// One-shot check of every chain that has an `expected_chain_id` configured.
///
/// TODO(#3764): covers Starknet only; extend as the other inspectors implement
/// [`ChainIdentity`].
pub(crate) async fn run(config: ForeignChainsConfig) {
    let inspectors: ForeignChainInspectors<HttpClient> =
        match ForeignChainInspectors::build(&config) {
            Ok(inspectors) => inspectors,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "foreign-chain identity check: failed to build inspectors"
                );
                return;
            }
        };

    if let (Some(chain_config), Some(chain_inspectors)) = (&config.starknet, &inspectors.starknet) {
        check_chain(dtos::ForeignChain::Starknet, chain_config, chain_inspectors).await;
    }
}

async fn check_chain<Inspector>(
    chain: dtos::ForeignChain,
    config: &ForeignChainConfig,
    inspectors: &FanOut<Inspector>,
) where
    Inspector: ChainIdentity + Clone + Send + Sync + 'static,
{
    let Some(expected) = config.expected_chain_id.as_deref() else {
        tracing::info!(
            ?chain,
            "foreign-chain identity check skipped: no expected_chain_id configured"
        );
        return;
    };

    let timeout = Duration::from_secs(config.timeout_sec.get());
    let identities = match tokio::time::timeout(timeout, inspectors.chain_identities()).await {
        Ok(identities) => identities,
        Err(_) => {
            tracing::warn!(?chain, ?timeout, "foreign-chain identity check timed out");
            return;
        }
    };

    // `ForeignChainInspectors` builds the fan-out in provider config order, so zipping
    // against the provider map restores each result's provider name.
    let observed: Vec<(RpcProviderName, Result<String, ForeignChainInspectionError>)> =
        config.providers.keys().cloned().zip(identities).collect();

    let diagnostics = compare_identities(chain, expected, &observed);
    if diagnostics.is_empty() {
        tracing::info!(
            ?chain,
            expected,
            "foreign-chain identity check: all providers report the expected chain identity"
        );
    }
    for diagnostic in &diagnostics {
        log_diagnostic(diagnostic);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityDiagnostic {
    chain: dtos::ForeignChain,
    provider: RpcProviderName,
    kind: IdentityDiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdentityDiagnosticKind {
    /// The provider answered with a different network identity than configured: it serves
    /// the wrong network and will break foreign-tx verification for this chain.
    Mismatch { expected: String, observed: String },
    /// The provider could not be queried; possibly transient, nothing definitive to report.
    Unreachable { error: String },
}

fn compare_identities(
    chain: dtos::ForeignChain,
    expected: &str,
    observed: &[(RpcProviderName, Result<String, ForeignChainInspectionError>)],
) -> Vec<IdentityDiagnostic> {
    observed
        .iter()
        .filter_map(|(provider, result)| {
            let kind = match result {
                Ok(identity) if identity == expected => return None,
                Ok(identity) => IdentityDiagnosticKind::Mismatch {
                    expected: expected.to_string(),
                    observed: identity.clone(),
                },
                Err(error) => IdentityDiagnosticKind::Unreachable {
                    error: error.to_string(),
                },
            };
            Some(IdentityDiagnostic {
                chain,
                provider: provider.clone(),
                kind,
            })
        })
        .collect()
}

fn log_diagnostic(diagnostic: &IdentityDiagnostic) {
    let chain = diagnostic.chain;
    let provider = diagnostic.provider.as_str();
    match &diagnostic.kind {
        IdentityDiagnosticKind::Mismatch { expected, observed } => {
            tracing::error!(
                ?chain,
                provider,
                expected,
                observed,
                "foreign-chain provider serves the wrong network"
            );
        }
        IdentityDiagnosticKind::Unreachable { error } => {
            tracing::warn!(
                ?chain,
                provider,
                error,
                "foreign-chain provider unreachable during identity check"
            );
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    const SN_MAIN: &str = "0x534e5f4d41494e";
    const SN_SEPOLIA: &str = "0x534e5f5345504f4c4941";

    fn provider(name: &str) -> RpcProviderName {
        RpcProviderName::from(name.to_string())
    }

    #[test]
    fn compare_identities__should_be_empty_when_all_providers_match() {
        // Given
        let observed = vec![
            (provider("alchemy"), Ok(SN_MAIN.to_string())),
            (provider("blast"), Ok(SN_MAIN.to_string())),
        ];

        // When
        let diagnostics = compare_identities(dtos::ForeignChain::Starknet, SN_MAIN, &observed);

        // Then
        assert!(
            diagnostics.is_empty(),
            "expected no diagnostics, got: {diagnostics:?}"
        );
    }

    #[test]
    fn compare_identities__should_emit_mismatch_naming_the_wrong_provider() {
        // Given: "blast" is configured against Sepolia instead of mainnet.
        let observed = vec![
            (provider("alchemy"), Ok(SN_MAIN.to_string())),
            (provider("blast"), Ok(SN_SEPOLIA.to_string())),
        ];

        // When
        let diagnostics = compare_identities(dtos::ForeignChain::Starknet, SN_MAIN, &observed);

        // Then
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].provider, provider("blast"));
        assert_matches!(
            &diagnostics[0].kind,
            IdentityDiagnosticKind::Mismatch { expected, observed }
                if expected == SN_MAIN && observed == SN_SEPOLIA
        );
    }

    #[test]
    fn compare_identities__should_emit_unreachable_when_provider_errors() {
        // Given
        let observed = vec![(
            provider("alchemy"),
            Err(ForeignChainInspectionError::RpcRequestFailed(
                "timeout".to_string(),
            )),
        )];

        // When
        let diagnostics = compare_identities(dtos::ForeignChain::Starknet, SN_MAIN, &observed);

        // Then
        assert_eq!(diagnostics.len(), 1);
        assert_matches!(
            &diagnostics[0].kind,
            IdentityDiagnosticKind::Unreachable { .. }
        );
    }

    #[test]
    fn compare_identities__should_report_each_provider_independently() {
        // Given: one healthy, one on the wrong network, one unreachable.
        let observed = vec![
            (provider("alchemy"), Ok(SN_MAIN.to_string())),
            (provider("blast"), Ok(SN_SEPOLIA.to_string())),
            (
                provider("quicknode"),
                Err(ForeignChainInspectionError::RpcRequestFailed(
                    "connection refused".to_string(),
                )),
            ),
        ];

        // When
        let diagnostics = compare_identities(dtos::ForeignChain::Starknet, SN_MAIN, &observed);

        // Then
        assert_eq!(diagnostics.len(), 2);
        assert_matches!(
            &diagnostics[0],
            IdentityDiagnostic { provider, kind: IdentityDiagnosticKind::Mismatch { .. }, .. }
                if *provider == RpcProviderName::from("blast".to_string())
        );
        assert_matches!(
            &diagnostics[1],
            IdentityDiagnostic { provider, kind: IdentityDiagnosticKind::Unreachable { .. }, .. }
                if *provider == RpcProviderName::from("quicknode".to_string())
        );
    }
}
