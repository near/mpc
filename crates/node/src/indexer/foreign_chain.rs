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

/// One read of [`ForeignChainRegistrations`].
struct RegistrationsSnapshot {
    supporters: ForeignChainSupporters,
    configs: dtos::ForeignChainsConfigs,
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
    let initial = loop {
        match read_registrations(&contract).await {
            Ok(registrations) => break registrations,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign-chain registrations from chain: {:?}", e);
                tokio::time::sleep(FOREIGN_CHAIN_REGISTRATIONS_REFRESH_INTERVAL).await;
            }
        }
    };

    let (supporters_sender, supporters) = watch::channel(initial.supporters);
    let (configs_sender, configs) = watch::channel(initial.configs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FOREIGN_CHAIN_REGISTRATIONS_REFRESH_INTERVAL).await;
            match read_registrations(&contract).await {
                Ok(latest) => {
                    send_if_changed(&supporters_sender, latest.supporters);
                    send_if_changed(&configs_sender, latest.configs);
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
) -> anyhow::Result<RegistrationsSnapshot> {
    let (available_chains, configs) = tokio::try_join!(
        contract.get_available_foreign_chains(),
        contract.get_foreign_chains_configs()
    )?;
    Ok(RegistrationsSnapshot {
        supporters: supporters_by_available_chain(&available_chains.value, &configs.value),
        configs: configs.value,
    })
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

/// Returns once the first whitelist is read, then keeps it updated in the background, like
/// [`monitor_foreign_chain_registrations`].
///
/// `probe_whitelist` receives the same whitelists, wrapped in `Some`. Its channel exists from
/// process start, for the foreign chain probe, which starts before the indexer has synced.
pub async fn monitor_foreign_chain_whitelist<V: ViewContract + Clone + Send + Sync + 'static>(
    contract: MpcContractHandle<V>,
    probe_whitelist: watch::Sender<Option<ForeignChainWhitelist>>,
) -> watch::Receiver<ForeignChainWhitelist> {
    let initial = fetch_foreign_chain_whitelist_with_retry(&contract).await;
    probe_whitelist.send_replace(Some(initial.clone()));
    let (sender, receiver) = watch::channel(initial);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL).await;
            let whitelist = fetch_foreign_chain_whitelist_with_retry(&contract).await;
            if *sender.borrow() == whitelist {
                continue;
            }
            probe_whitelist.send_replace(Some(whitelist.clone()));
            sender.send_replace(whitelist);
        }
    });
    receiver
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_contract_transport::mock::{MockViewContract, MockViewError};
    use near_contract_transport::{ObservedState, SerializedObservation};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::method_names::{
        GET_AVAILABLE_FOREIGN_CHAINS, GET_FOREIGN_CHAINS_CONFIGS,
    };
    use rstest::rstest;

    use super::*;

    fn whitelist(provider: &str) -> ForeignChainWhitelist {
        let config = dtos::ProviderConfig {
            base_url: format!("https://{provider}.example.com"),
            auth_scheme: dtos::AuthScheme::None,
            chain_routing: dtos::ChainRouting::Embedded,
        };
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(dtos::ProviderId(provider.to_string()), config),
            quorum: 1,
        };
        BTreeMap::from([(dtos::ForeignChain::Polygon, entry)])
    }

    fn observed(value: &impl serde::Serialize) -> Result<SerializedObservation, MockViewError> {
        Ok(ObservedState {
            observed_at: 0.into(),
            value: serde_json::to_vec(value).unwrap(),
        })
    }

    fn contract(viewer: &MockViewContract) -> MpcContractHandle<MockViewContract> {
        MpcContractHandle::new(viewer.clone(), "mpc.near".parse().unwrap())
    }

    #[tokio::test]
    async fn monitor_foreign_chain_whitelist__should_publish_the_first_whitelist_to_the_probe() {
        // Given
        let whitelist = whitelist("alchemy");
        let viewer = MockViewContract::new(observed(&whitelist));
        let (probe_whitelist, probe_rx) = watch::channel(None);

        // When
        let _whitelist_rx =
            monitor_foreign_chain_whitelist(contract(&viewer), probe_whitelist).await;

        // Then
        assert_eq!(*probe_rx.borrow(), Some(whitelist));
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_foreign_chain_whitelist__should_publish_a_changed_whitelist_to_the_probe() {
        // Given
        let changed = whitelist("quicknode");
        let viewer = MockViewContract::new(observed(&whitelist("alchemy")));
        let (probe_whitelist, mut probe_rx) = watch::channel(None);
        let _whitelist_rx =
            monitor_foreign_chain_whitelist(contract(&viewer), probe_whitelist).await;
        probe_rx.mark_unchanged();

        // When
        viewer.set_response(observed(&changed));
        tokio::time::timeout(Duration::from_mins(1), probe_rx.changed())
            .await
            .unwrap()
            .unwrap();

        // Then
        assert_eq!(*probe_rx.borrow(), Some(changed));
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_foreign_chain_whitelist__should_not_republish_an_unchanged_whitelist_to_the_probe()
     {
        // Given
        let viewer = MockViewContract::new(observed(&whitelist("alchemy")));
        let (probe_whitelist, mut probe_rx) = watch::channel(None);
        let _whitelist_rx =
            monitor_foreign_chain_whitelist(contract(&viewer), probe_whitelist).await;
        probe_rx.mark_unchanged();

        // When
        tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL * 5).await;

        // Then
        assert!(
            viewer.calls().len() > 1,
            "the monitor should have refreshed"
        );
        assert!(!probe_rx.has_changed().unwrap());
    }

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

    #[rstest]
    #[case::omit_chain_that_is_not_available(&[1], dtos::ForeignChain::Base, BTreeMap::new())]
    #[case::map_available_chain_to_supporting_tls_keys(
        &[1, 2],
        dtos::ForeignChain::Bitcoin,
        bitcoin_supporters(&[1, 2])
    )]
    fn supporters_by_available_chain__should_keep_only_the_available_chains(
        #[case] registered_seeds: &[u8],
        #[case] available_chain: dtos::ForeignChain,
        #[case] expected: ForeignChainSupporters,
    ) {
        // Given
        let configs: dtos::ForeignChainsConfigs = registered_seeds
            .iter()
            .map(|seed| (tls_key(*seed), bitcoin_config()))
            .collect::<BTreeMap<_, _>>()
            .into();
        let available: dtos::AvailableForeignChains = BTreeSet::from([available_chain]).into();

        // When
        let supporters = supporters_by_available_chain(&available, &configs);

        // Then
        assert_eq!(supporters, expected);
    }
}
