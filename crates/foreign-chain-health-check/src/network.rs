//! Network identifier for selecting golden reference transactions.

use mpc_node_config::{ChainId, HealthCheckGoldenConfig, NearInitConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn label(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

/// What kind of network the node runs against. Pure classification;
/// [`HealthCheckPlan::decide`] turns it into an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    /// A public network (mainnet/testnet) with a built-in golden set.
    Public(Network),
    /// Localnet/sandbox/custom chain or a fork — no built-in golden set.
    Local,
    /// Network could not be determined.
    Undetermined,
}

/// The decided health-check action — one variant per behavior, built by
/// [`HealthCheckPlan::decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthCheckPlan {
    /// Built-in golden set. No golden field — a supplied one can't reach here.
    ProbeBuiltIn(Network),
    /// Operator-supplied golden. Boxed to keep the enum small.
    ProbeSupplied(Box<HealthCheckGoldenConfig>),
    /// Do not probe.
    Skip(SkipReason),
}

/// Why the startup health check does not probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Local/sandbox/custom chain with no golden values supplied.
    LocalChainWithoutGolden,
    /// Network could not be determined.
    Undetermined,
}

/// Resolve the network kind: `near_init.chain_id` if present, else the
/// contract-id suffix. A local chain never falls back to the contract id — a
/// mainnet fork pointed at a `.near` contract must not probe real mainnet.
pub fn resolve_network_from_config(
    near_init: Option<&NearInitConfig>,
    contract_id: &str,
) -> NetworkKind {
    match near_init {
        Some(near_init) => match near_init.chain_id {
            ChainId::Mainnet => NetworkKind::Public(Network::Mainnet),
            ChainId::Testnet => NetworkKind::Public(Network::Testnet),
            ChainId::Localnet | ChainId::Sandbox | ChainId::Custom(_) => NetworkKind::Local,
        },
        None => match network_from_contract_id(contract_id) {
            Some(network) => NetworkKind::Public(network),
            None => NetworkKind::Undetermined,
        },
    }
}

impl HealthCheckPlan {
    /// Fold the supplied golden into the resolved network — the sole home of the
    /// golden-precedence rule:
    /// - public → built-in set (a supplied golden is dropped);
    /// - local → supplied golden, else skip;
    /// - undetermined → skip.
    pub fn decide(network: NetworkKind, golden: Option<HealthCheckGoldenConfig>) -> Self {
        match network {
            NetworkKind::Public(network) => Self::ProbeBuiltIn(network),
            NetworkKind::Local => match golden {
                Some(golden) => Self::ProbeSupplied(Box::new(golden)),
                None => Self::Skip(SkipReason::LocalChainWithoutGolden),
            },
            NetworkKind::Undetermined => Self::Skip(SkipReason::Undetermined),
        }
    }
}

/// Classify mainnet/testnet from a contract-id suffix.
pub fn network_from_contract_id(contract_id: &str) -> Option<Network> {
    if contract_id.ends_with(".testnet") {
        Some(Network::Testnet)
    } else if contract_id.ends_with(".near") || contract_id == "v1.signer" {
        Some(Network::Mainnet)
    } else {
        None
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    fn near_init(chain_id: ChainId) -> NearInitConfig {
        NearInitConfig {
            chain_id,
            boot_nodes: None,
            genesis_path: None,
            download_config: None,
            download_config_url: None,
            download_genesis: false,
            download_genesis_url: None,
            download_genesis_records_url: None,
            rpc_addr: None,
            network_addr: None,
            tier3_public_addr: None,
        }
    }

    #[test]
    fn resolve_network_from_config__should_trust_chain_id_over_contract_id() {
        for (chain_id, contract_id, expected) in [
            (ChainId::Testnet, "v1.signer.near", Network::Testnet),
            (ChainId::Mainnet, "foo.testnet", Network::Mainnet),
        ] {
            // Given a chain_id contradicting the contract id
            let init = near_init(chain_id);

            // When
            let network = resolve_network_from_config(Some(&init), contract_id);

            // Then chain_id wins — no contract-id fallback
            assert_eq!(network, NetworkKind::Public(expected));
        }
    }

    #[test]
    fn resolve_network_from_config__should_report_local_chain_for_non_mainnet_testnet_chain_ids() {
        for chain_id in [
            ChainId::Localnet,
            ChainId::Sandbox,
            ChainId::Custom("sandbox".to_string()),
        ] {
            // Given a local/fork chain pointed at a mainnet-looking contract id
            let init = near_init(chain_id.clone());

            // When
            let network = resolve_network_from_config(Some(&init), "v1.signer.near");

            // Then it is a known local chain, not misclassified as mainnet
            assert_eq!(
                network,
                NetworkKind::Local,
                "expected Local for {chain_id:?}"
            );
        }
    }

    #[test]
    fn resolve_network_from_config__should_fall_back_to_contract_id_without_near_init() {
        assert_eq!(
            resolve_network_from_config(None, "foo.testnet"),
            NetworkKind::Public(Network::Testnet)
        );
        assert_eq!(
            resolve_network_from_config(None, "foo.near"),
            NetworkKind::Public(Network::Mainnet)
        );
        assert_eq!(
            resolve_network_from_config(None, "v1.signer"),
            NetworkKind::Public(Network::Mainnet)
        );
    }

    #[test]
    fn resolve_network_from_config__should_be_undetermined_without_near_init_or_known_contract() {
        assert_eq!(
            resolve_network_from_config(None, "mpc.sandbox"),
            NetworkKind::Undetermined
        );
    }

    #[test]
    fn decide__should_probe_builtin_and_drop_golden_on_a_public_network() {
        // Given a public network AND a config-supplied golden
        let plan = HealthCheckPlan::decide(NetworkKind::Public(Network::Mainnet), Some(golden()));

        // Then the built-in set is used and the golden is dropped (unrepresentable)
        assert_eq!(plan, HealthCheckPlan::ProbeBuiltIn(Network::Mainnet));
    }

    #[test]
    fn decide__should_probe_with_supplied_golden_on_a_local_chain() {
        // Given a local chain with supplied golden values
        let golden = golden();
        let plan = HealthCheckPlan::decide(NetworkKind::Local, Some(golden.clone()));

        // Then those values drive the probe
        assert_eq!(plan, HealthCheckPlan::ProbeSupplied(Box::new(golden)));
    }

    #[test]
    fn decide__should_skip_a_local_chain_without_golden() {
        // Given a local chain and no golden
        let plan = HealthCheckPlan::decide(NetworkKind::Local, None);

        // Then it skips, distinguishing the reason for the caller's log level
        assert_eq!(
            plan,
            HealthCheckPlan::Skip(SkipReason::LocalChainWithoutGolden)
        );
    }

    #[test]
    fn decide__should_skip_when_undetermined_even_with_golden() {
        // Given an undetermined network, a supplied golden must not make it probe
        let plan = HealthCheckPlan::decide(NetworkKind::Undetermined, Some(golden()));

        // Then it skips
        assert_eq!(plan, HealthCheckPlan::Skip(SkipReason::Undetermined));
    }

    fn golden() -> HealthCheckGoldenConfig {
        HealthCheckGoldenConfig::default()
    }
}
