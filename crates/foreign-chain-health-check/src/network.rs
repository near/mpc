//! Network identifier for selecting golden reference transactions.

use mpc_node_config::{ChainId, NearInitConfig};

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

/// Whether the startup health check should probe, or skip and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkResolution {
    Probe(Network),
    Skip(SkipReason),
}

/// Why the startup health check is skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Localnet/sandbox/custom chain — no golden vectors.
    LocalChain,
    /// Network could not be determined.
    Undetermined,
}

/// Resolve which network to probe: use `near_init.chain_id` if present, else the
/// contract-id suffix. A local chain never falls back to the contract id — a
/// fork of mainnet pointed at a `.near` contract must not probe real mainnet
/// endpoints.
pub fn resolve_network_from_config(
    near_init: Option<&NearInitConfig>,
    contract_id: &str,
) -> NetworkResolution {
    match near_init {
        Some(near_init) => match near_init.chain_id {
            ChainId::Mainnet => NetworkResolution::Probe(Network::Mainnet),
            ChainId::Testnet => NetworkResolution::Probe(Network::Testnet),
            ChainId::Localnet | ChainId::Sandbox | ChainId::Custom(_) => {
                NetworkResolution::Skip(SkipReason::LocalChain)
            }
        },
        None => match network_from_contract_id(contract_id) {
            Some(network) => NetworkResolution::Probe(network),
            None => NetworkResolution::Skip(SkipReason::Undetermined),
        },
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
            assert_eq!(network, NetworkResolution::Probe(expected));
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
                NetworkResolution::Skip(SkipReason::LocalChain),
                "expected LocalChain for {chain_id:?}"
            );
        }
    }

    #[test]
    fn resolve_network_from_config__should_fall_back_to_contract_id_without_near_init() {
        assert_eq!(
            resolve_network_from_config(None, "foo.testnet"),
            NetworkResolution::Probe(Network::Testnet)
        );
        assert_eq!(
            resolve_network_from_config(None, "foo.near"),
            NetworkResolution::Probe(Network::Mainnet)
        );
        assert_eq!(
            resolve_network_from_config(None, "v1.signer"),
            NetworkResolution::Probe(Network::Mainnet)
        );
    }

    #[test]
    fn resolve_network_from_config__should_be_undetermined_without_near_init_or_known_contract() {
        assert_eq!(
            resolve_network_from_config(None, "mpc.sandbox"),
            NetworkResolution::Skip(SkipReason::Undetermined)
        );
    }
}
