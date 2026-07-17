use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// TLS keys of the nodes whose registered config supports each available chain.
pub type ForeignChainSupporters = BTreeMap<dtos::ForeignChain, BTreeSet<dtos::Ed25519PublicKey>>;

/// Publishes the contract's available chains mapped to their registered
/// supporters. Failed reads are retried with backoff; the previously
/// published value stays in effect until a read succeeds.
pub async fn monitor_foreign_chain_supporters(
    sender: watch::Sender<ForeignChainSupporters>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        let supporters = fetch_with_retry(
            || read_supporters(&indexer_state),
            "error reading foreign-chain supporters from chain",
        )
        .await;
        publish_if_changed(&sender, supporters);
        tokio::time::sleep(FOREIGN_CHAIN_SUPPORTERS_REFRESH_INTERVAL).await;
    }
}

/// TODO(#1956): share the retry loop with the monitors in `indexer::tee`.
async fn fetch_with_retry<T, Fetch, FetchFuture>(fetch: Fetch, error_context: &str) -> T
where
    Fetch: Fn() -> FetchFuture,
    FetchFuture: Future<Output = anyhow::Result<T>>,
{
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match fetch().await {
            Ok(value) => return value,
            Err(e) => {
                tracing::error!(target: "mpc", "{error_context}: {:?}", e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

fn publish_if_changed<T: PartialEq>(sender: &watch::Sender<T>, value: T) -> bool {
    sender.send_if_modified(|previous| {
        if *previous == value {
            false
        } else {
            *previous = value;
            true
        }
    })
}

/// The two view calls are not atomic: a change finalized between them yields
/// a transiently inconsistent snapshot, corrected on the next poll.
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
    use std::cell::Cell;

    fn tls_key(seed: u8) -> dtos::Ed25519PublicKey {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        dtos::Ed25519PublicKey::from(&signing_key.verifying_key())
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

    #[test]
    fn publish_if_changed__should_publish_a_changed_value() {
        // Given
        let (sender, receiver) = watch::channel(ForeignChainSupporters::new());
        let supporters = bitcoin_supporters(&[1]);

        // When
        let published = publish_if_changed(&sender, supporters.clone());

        // Then
        assert!(published);
        assert_eq!(*receiver.borrow(), supporters);
    }

    #[test]
    fn publish_if_changed__should_not_publish_an_unchanged_value() {
        // Given
        let (sender, mut receiver) = watch::channel(bitcoin_supporters(&[1]));
        receiver.mark_unchanged();

        // When
        let published = publish_if_changed(&sender, bitcoin_supporters(&[1]));

        // Then
        assert!(!published);
        assert!(!receiver.has_changed().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_with_retry__should_keep_retrying_until_fetch_succeeds() {
        // Given: a fetch that fails twice before succeeding.
        let attempts = Cell::new(0);
        let fetch = || {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            async move {
                if attempt < 3 {
                    anyhow::bail!("rpc unavailable");
                }
                Ok(attempt)
            }
        };

        // When
        let value = fetch_with_retry(fetch, "test").await;

        // Then
        assert_eq!(value, 3);
    }
}
