use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use near_contract_transport::ViewContract;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

const FOREIGN_CHAIN_REGISTRATIONS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_mins(1);

/// Both receivers are fed by one poll of the contract.
pub struct ForeignChainRegistrations {
    pub supporters: watch::Receiver<ForeignChainSupporters>,
    /// The foreign chains each node registered, keyed by TLS key.
    pub configs: watch::Receiver<dtos::ForeignChainsConfigs>,
}

/// TLS keys of the nodes whose registered config supports each available chain.
pub type ForeignChainSupporters = BTreeMap<dtos::ForeignChain, BTreeSet<dtos::Ed25519PublicKey>>;

/// The contract's voted RPC providers and quorum per chain.
pub type ForeignChainWhitelist = BTreeMap<dtos::ForeignChain, dtos::ChainEntry>;

/// Returns once the first snapshot is read, then keeps it updated in the background.
/// Mirrors [`monitor_contract_state`](super::participants::monitor_contract_state): the receivers
/// always hold a real value, and a failed refresh keeps the previous one.
pub async fn monitor_foreign_chain_registrations<
    V: ViewContract + Clone + Send + Sync + 'static,
>(
    contract: MpcContractHandle<V>,
) -> ForeignChainRegistrations {
    let (initial_supporters, initial_configs) = loop {
        match read_registrations(&contract).await {
            Ok(registrations) => break registrations,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign-chain registrations from chain: {:?}", e);
                tokio::time::sleep(FOREIGN_CHAIN_REGISTRATIONS_REFRESH_INTERVAL).await;
            }
        }
    };

    let (supporters_sender, supporters) = watch::channel(initial_supporters);
    let (configs_sender, configs) = watch::channel(initial_configs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FOREIGN_CHAIN_REGISTRATIONS_REFRESH_INTERVAL).await;
            match read_registrations(&contract).await {
                Ok((latest_supporters, latest_configs)) => {
                    send_if_changed(&supporters_sender, latest_supporters);
                    send_if_changed(&configs_sender, latest_configs);
                }
                Err(e) => {
                    tracing::error!(target: "mpc", "error reading foreign-chain registrations from chain: {:?}", e)
                }
            }
        }
    });
    ForeignChainRegistrations {
        supporters,
        configs,
    }
}

/// The two view calls are not atomic: a change finalized between them yields
/// a transiently inconsistent snapshot, corrected on the next poll.
async fn read_registrations<C: ViewContract + Clone + Send + 'static>(
    contract: &MpcContractHandle<C>,
) -> anyhow::Result<(ForeignChainSupporters, dtos::ForeignChainsConfigs)> {
    let (available_chains, configs) = tokio::try_join!(
        contract.get_available_foreign_chains(),
        contract.get_foreign_chains_configs()
    )?;
    let supporters = supporters_by_available_chain(&available_chains.value, &configs.value);
    Ok((supporters, configs.value))
}

fn send_if_changed<T: PartialEq>(sender: &watch::Sender<T>, latest: T) {
    sender.send_if_modified(|previous| {
        if *previous == latest {
            false
        } else {
            *previous = latest;
            true
        }
    });
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
async fn fetch_foreign_chain_whitelist_with_retry<C: ViewContract + Clone + Send + 'static>(
    contract: &MpcContractHandle<C>,
) -> ForeignChainWhitelist {
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match contract.allowed_foreign_chain_providers().await {
            Ok(observed) => return observed.value,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading allowed_foreign_chain_providers from chain: {:?}", e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

/// Returns once the first whitelist is read, then keeps it updated in the background.
pub async fn monitor_foreign_chain_whitelist<V: ViewContract + Clone + Send + Sync + 'static>(
    contract: MpcContractHandle<V>,
) -> watch::Receiver<ForeignChainWhitelist> {
    let initial = fetch_foreign_chain_whitelist_with_retry(&contract).await;
    let (sender, receiver) = watch::channel(initial);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL).await;
            let whitelist = fetch_foreign_chain_whitelist_with_retry(&contract).await;
            sender.send_if_modified(|previous| {
                if *previous != whitelist {
                    *previous = whitelist;
                    true
                } else {
                    false
                }
            });
        }
    });
    receiver
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_contract_transport::mock::{MockViewContract, MockViewError};
    use near_contract_transport::{ObservedState, SerializedObservation};
    use near_mpc_contract_interface::method_names::{
        GET_AVAILABLE_FOREIGN_CHAINS, GET_FOREIGN_CHAINS_CONFIGS,
    };

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

    fn observed(value: &impl serde::Serialize) -> Result<SerializedObservation, MockViewError> {
        Ok(ObservedState {
            observed_at: 0.into(),
            value: serde_json::to_vec(value).unwrap(),
        })
    }

    #[tokio::test]
    async fn monitor_foreign_chain_registrations__should_publish_the_configs_the_contract_returns()
    {
        // Given
        let configs: dtos::ForeignChainsConfigs =
            BTreeMap::from([(tls_key(1), bitcoin_config())]).into();
        let viewer = MockViewContract::new(Err(MockViewError("unexpected view")));
        viewer.set_view_response_for_method(
            GET_AVAILABLE_FOREIGN_CHAINS,
            observed(&dtos::AvailableForeignChains::default()),
        );
        viewer.set_view_response_for_method(GET_FOREIGN_CHAINS_CONFIGS, observed(&configs));
        let contract = MpcContractHandle::new(viewer, "mpc.near".parse().unwrap());

        // When
        let registrations = monitor_foreign_chain_registrations(contract).await;

        // Then
        assert_eq!(*registrations.configs.borrow(), configs);
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
