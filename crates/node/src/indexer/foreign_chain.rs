use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const FOREIGN_CHAIN_POLICY_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// TLS keys of the nodes whose registered config supports each available chain.
pub type ForeignChainSupporters = BTreeMap<dtos::ForeignChain, HashSet<dtos::Ed25519PublicKey>>;

/// Publishes the contract's available chains mapped to their registered
/// supporters. On read errors the previously published value stays in effect.
pub async fn monitor_foreign_chain_supporters(
    sender: watch::Sender<ForeignChainSupporters>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        match read_supporters(&indexer_state).await {
            Ok(supporters) => {
                sender.send_if_modified(|previous| {
                    if *previous != supporters {
                        *previous = supporters;
                        true
                    } else {
                        false
                    }
                });
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign-chain policy from chain: {:?}", e);
            }
        }
        tokio::time::sleep(FOREIGN_CHAIN_POLICY_REFRESH_INTERVAL).await;
    }
}

async fn read_supporters(indexer_state: &IndexerState) -> anyhow::Result<ForeignChainSupporters> {
    let (_height, available_chains) = indexer_state
        .view_client
        .get_available_chains(&indexer_state.mpc_contract_id)
        .await?;
    let (_height, configs) = indexer_state
        .view_client
        .get_foreign_chains_configs(&indexer_state.mpc_contract_id)
        .await?;
    Ok(supporters_by_available_chain(&available_chains, &configs))
}

/// Maps each available chain to the TLS keys registered as supporting it;
/// chains that are not available are omitted.
pub(crate) fn supporters_by_available_chain(
    available_chains: &dtos::AvailableForeignChains,
    configs: &dtos::ForeignChainsConfigs,
) -> ForeignChainSupporters {
    let mut supporters: ForeignChainSupporters = BTreeMap::new();
    for (tls_key, config) in configs.iter() {
        for chain in config.iter() {
            if available_chains.contains(chain) {
                supporters
                    .entry(*chain)
                    .or_default()
                    .insert(tls_key.clone());
            }
        }
    }
    supporters
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;

    fn tls_key(seed: u8) -> dtos::Ed25519PublicKey {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        dtos::Ed25519PublicKey::from(&signing_key.verifying_key())
    }

    fn bitcoin_config() -> dtos::ForeignChainsConfig {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    #[test]
    fn supporters_by_available_chain__should_omit_chain_that_is_not_available() {
        // Given: a node registered for Bitcoin while only Base is available.
        let configs: dtos::ForeignChainsConfigs =
            BTreeMap::from([(tls_key(1), bitcoin_config())]).into();
        let available: dtos::AvailableForeignChains =
            BTreeSet::from([dtos::ForeignChain::Base]).into();

        // When
        let supporters = supporters_by_available_chain(&available, &configs);

        // Then
        assert!(supporters.is_empty());
    }

    #[test]
    fn supporters_by_available_chain__should_map_available_chain_to_supporting_tls_keys() {
        // Given: two nodes registered for Bitcoin, which is available.
        let configs: dtos::ForeignChainsConfigs = BTreeMap::from([
            (tls_key(1), bitcoin_config()),
            (tls_key(2), bitcoin_config()),
        ])
        .into();
        let available: dtos::AvailableForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();

        // When
        let supporters = supporters_by_available_chain(&available, &configs);

        // Then
        assert_eq!(
            supporters,
            BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                HashSet::from([tls_key(1), tls_key(2)]),
            )])
        );
    }
}
