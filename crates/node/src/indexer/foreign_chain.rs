use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL: Duration = Duration::from_mins(5);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_mins(1);

/// TLS keys of the nodes whose registered config supports each available chain.
pub type ForeignChainSupporters = BTreeMap<dtos::ForeignChain, BTreeSet<dtos::Ed25519PublicKey>>;

/// Returns once the first supporters snapshot is read, then keeps it updated in
/// the background. Mirrors `monitor_contract_state`: the receiver always holds a
/// real value, and a failed refresh keeps the previous one.
pub async fn monitor_foreign_chain_supporters(
    indexer_state: Arc<IndexerState>,
) -> watch::Receiver<ForeignChainSupporters> {
    indexer_state.client.wait_for_full_sync().await;

    let initial = loop {
        match read_supporters(&indexer_state).await {
            Ok(supporters) => break supporters,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign-chain supporters from chain: {:?}", e);
                tokio::time::sleep(FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL).await;
            }
        }
    };

    let (sender, receiver) = watch::channel(initial);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL).await;
            match read_supporters(&indexer_state).await {
                Ok(supporters) => {
                    sender.send_if_modified(|previous| {
                        if *previous == supporters {
                            false
                        } else {
                            *previous = supporters;
                            true
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(target: "mpc", "error reading foreign-chain supporters from chain: {:?}", e)
                }
            }
        }
    });
    receiver
}

/// The two view calls are not atomic: a change finalized between them yields
/// a transiently inconsistent snapshot, corrected on the next poll.
async fn read_supporters(indexer_state: &IndexerState) -> anyhow::Result<ForeignChainSupporters> {
    let ((_, available_chains), (_, configs)) = tokio::try_join!(
        indexer_state.view_client.get_available_chains(),
        indexer_state.view_client.get_foreign_chains_configs()
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

/// Fetches the allowed foreign-chain providers whitelist from the contract with retry logic.
async fn fetch_foreign_chain_whitelist_with_retry(
    indexer_state: &IndexerState,
) -> BTreeMap<dtos::ForeignChain, dtos::ChainEntry> {
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match indexer_state
            .view_client
            .get_allowed_foreign_chain_providers()
            .await
        {
            Ok(whitelist) => return whitelist,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading allowed_foreign_chain_providers from chain: {:?}", e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

/// Monitor the allowed foreign-chain providers whitelist stored in the contract and update the
/// watch channel when changes are detected. Consumed by
/// [`crate::foreign_chain_whitelist_verifier::run`].
pub async fn monitor_foreign_chain_whitelist(
    sender: watch::Sender<BTreeMap<dtos::ForeignChain, dtos::ChainEntry>>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        let whitelist = fetch_foreign_chain_whitelist_with_retry(&indexer_state).await;
        sender.send_if_modified(|previous| {
            if *previous != whitelist {
                *previous = whitelist;
                true
            } else {
                false
            }
        });
        tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL).await;
    }
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
