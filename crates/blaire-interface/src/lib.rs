//! Types exchanged between MPC nodes and Blaire.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

/// Report an MPC node publishes to Blaire at startup.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct NodeReport {
    pub version: Version,
    pub redacted_config: RedactedForeignChainsConfig,
}

/// Version of the MPC node software that sent the report, e.g. "3.2.0".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Version(pub String);

/// Foreign chain configuration published by an MPC node at startup.
///
/// Built field-by-field from the node's `ForeignChainsConfig` as an allowlist:
/// a field added upstream is not published until it is added here.
/// Secrets never leave the node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RedactedForeignChainsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ethereum: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "abstract")]
    pub abstract_chain: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starknet: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bnb: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arbitrum: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hyper_evm: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polygon: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aptos: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sui: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avalanche: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adi: Option<RedactedForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fogo: Option<RedactedForeignChainConfig>,
}

/// Debug-relevant settings for one foreign chain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RedactedForeignChainConfig {
    pub timeout_sec: NonZeroU64,
    /// Total attempts per provider; `1` means a single try.
    pub max_retries: NonZeroU64,
    /// Chain id or genesis hash the operator expects providers to report.
    pub expected_network_fingerprint: Option<String>,
    /// Keyed by the operator's provider name, e.g. "alchemy".
    pub providers: BTreeMap<String, RedactedProviderConfig>,
}

/// One RPC provider, with all credentials removed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RedactedProviderConfig {
    /// Scheme and host of the RPC URL only, e.g. `https://eth-mainnet.g.alchemy.com`.
    /// Path, query and userinfo are dropped because they can contain API keys.
    pub rpc_origin: String,
    /// How the provider authenticates. The credential itself is never published.
    pub auth: AuthKind,
}

/// The kind of authentication a provider uses, without any token data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    None,
    Header,
    Path,
    Query,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    /// A report that exercises every serde attribute of the wire format.
    fn example_report() -> NodeReport {
        let providers = BTreeMap::from([
            provider("public", "https://rpc.example.org", AuthKind::None),
            provider(
                "alchemy",
                "https://eth-mainnet.g.alchemy.com",
                AuthKind::Header,
            ),
            provider("infura", "https://mainnet.infura.io", AuthKind::Path),
            provider("quicknode", "https://example.quiknode.pro", AuthKind::Query),
        ]);
        let chain = RedactedForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).expect("30 is non-zero"),
            max_retries: NonZeroU64::new(3).expect("3 is non-zero"),
            expected_network_fingerprint: Some("1".to_string()),
            providers,
        };
        NodeReport {
            version: Version("3.18.0".to_string()),
            redacted_config: RedactedForeignChainsConfig {
                ethereum: Some(chain.clone()),
                abstract_chain: Some(chain),
                ..Default::default()
            },
        }
    }

    fn provider(name: &str, origin: &str, auth: AuthKind) -> (String, RedactedProviderConfig) {
        (
            name.to_string(),
            RedactedProviderConfig {
                rpc_origin: origin.to_string(),
                auth,
            },
        )
    }

    #[test]
    fn node_report_serializes_to_expected_json() {
        // Given
        let report = example_report();

        // When
        let json = serde_json::to_value(&report).expect("serialization succeeds");

        // Then
        insta::assert_json_snapshot!(json);
    }

    #[test]
    fn node_report_survives_json_round_trip() {
        // Given
        let report = example_report();

        // When
        let json = serde_json::to_string(&report).expect("serialization succeeds");
        let parsed: NodeReport = serde_json::from_str(&json).expect("deserialization succeeds");

        // Then
        assert_eq!(parsed, report);
    }
}
