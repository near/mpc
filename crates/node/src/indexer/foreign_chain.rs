use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// TLS keys of the nodes whose registered config supports each available chain.
pub type ForeignChainSupporters = BTreeMap<dtos::ForeignChain, BTreeSet<dtos::Ed25519PublicKey>>;

/// Updates the contract's available chains mapped to their registered
/// supporters in watch channel.
/// The channel holds `None` until the first successful read; afterwards the
/// previously published value stays in effect until viewing new state from
/// contract succeeds.
pub async fn monitor_foreign_chain_supporters(
    sender: watch::Sender<Option<ForeignChainSupporters>>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        match read_supporters(&indexer_state).await {
            Ok(supporters) => {
                sender.send_if_modified(|previous| {
                    if previous.as_ref() == Some(&supporters) {
                        false
                    } else {
                        *previous = Some(supporters);
                        true
                    }
                });
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign-chain supporters from chain: {:?}", e)
            }
        }
        tokio::time::sleep(FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL).await;
    }
}

/// The two view calls are not atomic: a change finalized between them yields
/// a transiently inconsistent snapshot, corrected on the next poll.
async fn read_supporters(indexer_state: &IndexerState) -> anyhow::Result<ForeignChainSupporters> {
    let ((_, available_chains), (_, configs)) = tokio::try_join!(
        indexer_state
            .view_client
            .get_available_chains(&indexer_state.mpc_contract_id),
        indexer_state
            .view_client
            .get_foreign_chains_configs(&indexer_state.mpc_contract_id)
    )?;
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

    fn tls_key(seed: u8) -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([seed; 32])
    }

    fn bitcoin_config() -> dtos::ForeignChainsConfig {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    fn bitcoin_supporters(seeds: &[u8]) -> ForeignChainSupporters {
        BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            seeds.iter().map(|seed| tls_key(*seed)).collect(),
        )])
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
        assert_eq!(supporters, bitcoin_supporters(&[1, 2]));
    }
}
