//! Registers on the contract the foreign chains this node can serve, and keeps that registration
//! in step with the whitelist.

use std::collections::{BTreeMap, BTreeSet};

use mpc_node_config::ForeignChainsConfig;
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::foreign_chain_rpc_policy::{RpcQuorumStatus, eligible_chains, rpc_quorum_statuses};
use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::indexer::tx_sender::{TransactionProcessorError, TransactionSender};
use crate::indexer::types::ChainSendTransactionRequest;
use crate::metrics;
use crate::tracking::{self, AutoAbortTask};

/// Registers the eligible chains now and again after every whitelist change that alters them.
/// Must be called from a tracked task. Dropping the returned task stops the registrar.
pub(crate) fn spawn_foreign_chains_registrar(
    txn_sender: impl TransactionSender + 'static,
    mut whitelist: watch::Receiver<ForeignChainWhitelist>,
    local: ForeignChainsConfig,
) -> AutoAbortTask<()> {
    tracking::spawn("foreign chains registrar", async move {
        let mut registered: Option<BTreeSet<dtos::ForeignChain>> = None;
        loop {
            let statuses = rpc_quorum_statuses(&local, &whitelist.borrow_and_update());
            publish_rpc_quorum_metrics(&statuses);
            let eligible = eligible_chains(&statuses);
            if registered.as_ref() != Some(&eligible) {
                match register_foreign_chains(&txn_sender, &eligible).await {
                    Ok(()) => registered = Some(eligible),
                    Err(TransactionProcessorError::ProcessorIsClosed) => break,
                }
            }
            if whitelist.changed().await.is_err() {
                break;
            }
        }
    })
}

/// An empty set is still sent, so the contract drops this node as a supporter of every chain.
async fn register_foreign_chains(
    txn_sender: &impl TransactionSender,
    chains: &BTreeSet<dtos::ForeignChain>,
) -> Result<(), TransactionProcessorError> {
    tracing::info!(
        ?chains,
        "registering the foreign chains this node can serve"
    );
    txn_sender
        .send(ChainSendTransactionRequest::RegisterForeignChainsConfig(
            contract_args::RegisterForeignChainsConfigArgs::new(chains.clone().into()),
        ))
        .await
        .inspect_err(|err| {
            tracing::warn!(error = ?err, "failed to send register foreign chains config transaction")
        })
}

/// Resets both gauges first, so a chain without a status loses its series.
fn publish_rpc_quorum_metrics(statuses: &BTreeMap<dtos::ForeignChain, RpcQuorumStatus>) {
    metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED.reset();
    metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED.reset();
    for (chain, status) in statuses {
        let labels = [chain.label()];
        metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED
            .with_label_values(&labels)
            .set(i64::try_from(status.required_whitelisted_providers.get()).unwrap_or(i64::MAX));
        metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED
            .with_label_values(&labels)
            .set(i64::try_from(status.configured_whitelisted_providers).unwrap_or(i64::MAX));
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::num::NonZeroU64;
    use std::time::Duration;

    use mpc_node_config::foreign_chains::RpcProviderName;
    use mpc_node_config::{AuthConfig, ForeignChainConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{
        AuthScheme, ChainEntry, ChainRouting, ForeignChain, ProviderConfig, ProviderId,
    };
    use prometheus::core::Collector;
    use std::assert_matches;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::tests::common::MockTransactionSender;
    use crate::tracking::start_root_task;

    const RPC_URL: &str = "https://eth.alchemy.com/";

    fn local_chain() -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                RpcProviderName::from("my-alchemy".to_string()),
                ForeignChainProviderConfig {
                    rpc_url: RPC_URL.to_string(),
                    auth: AuthConfig::None,
                },
            ),
            expected_network_fingerprint: None,
        }
    }

    fn entry(quorum: u64) -> ChainEntry {
        ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId("alchemy".to_string()),
                ProviderConfig {
                    base_url: RPC_URL.to_string(),
                    auth_scheme: AuthScheme::None,
                    chain_routing: ChainRouting::Embedded,
                },
            ),
            quorum,
        }
    }

    fn registered_chains(request: ChainSendTransactionRequest) -> dtos::ForeignChainsConfig {
        match request {
            ChainSendTransactionRequest::RegisterForeignChainsConfig(args) => {
                args.foreign_chains_config
            }
            other => panic!("expected a registration, got {other:?}"),
        }
    }

    fn chains(chains: &[ForeignChain]) -> dtos::ForeignChainsConfig {
        chains.iter().copied().collect::<BTreeSet<_>>().into()
    }

    async fn next_registration(
        receiver: &mut mpsc::Receiver<ChainSendTransactionRequest>,
    ) -> dtos::ForeignChainsConfig {
        let request = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timed out waiting for a registration")
            .expect("transaction sender dropped");
        registered_chains(request)
    }

    /// Ethereum is configured and whitelisted with a reachable quorum.
    #[tokio::test]
    async fn spawn_foreign_chains_registrar__should_register_the_eligible_chains_on_start() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let local = ForeignChainsConfig {
                ethereum: Some(local_chain()),
                ..Default::default()
            };
            let (_whitelist_sender, whitelist) = watch::channel(ForeignChainWhitelist::from([(
                ForeignChain::Ethereum,
                entry(1),
            )]));
            let (sender, mut receiver) = mpsc::channel(10);

            // When
            let _registrar = spawn_foreign_chains_registrar(
                MockTransactionSender {
                    transaction_sender: sender,
                },
                whitelist,
                local,
            );

            // Then
            assert_eq!(
                next_registration(&mut receiver).await,
                chains(&[ForeignChain::Ethereum])
            );
        });
        root.await;
    }

    /// Ethereum is configured but not whitelisted at start. The whitelist then makes it eligible.
    #[tokio::test]
    async fn spawn_foreign_chains_registrar__should_reregister_when_the_eligible_chains_change() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let local = ForeignChainsConfig {
                ethereum: Some(local_chain()),
                ..Default::default()
            };
            let (whitelist_sender, whitelist) = watch::channel(ForeignChainWhitelist::new());
            let (sender, mut receiver) = mpsc::channel(10);
            let _registrar = spawn_foreign_chains_registrar(
                MockTransactionSender {
                    transaction_sender: sender,
                },
                whitelist,
                local,
            );
            assert_eq!(next_registration(&mut receiver).await, chains(&[]));

            // When
            whitelist_sender
                .send(ForeignChainWhitelist::from([(
                    ForeignChain::Ethereum,
                    entry(1),
                )]))
                .unwrap();

            // Then
            assert_eq!(
                next_registration(&mut receiver).await,
                chains(&[ForeignChain::Ethereum])
            );
        });
        root.await;
    }

    /// Ethereum is registered. Whitelisting a chain this node does not run changes nothing, so no
    /// registration follows. Raising Ethereum's quorum out of reach then registers an empty set.
    #[tokio::test]
    async fn spawn_foreign_chains_registrar__should_skip_a_whitelist_change_that_keeps_the_eligible_chains()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let local = ForeignChainsConfig {
                ethereum: Some(local_chain()),
                ..Default::default()
            };
            let (whitelist_sender, whitelist) = watch::channel(ForeignChainWhitelist::from([(
                ForeignChain::Ethereum,
                entry(1),
            )]));
            let (sender, mut receiver) = mpsc::channel(10);
            let _registrar = spawn_foreign_chains_registrar(
                MockTransactionSender {
                    transaction_sender: sender,
                },
                whitelist,
                local,
            );
            assert_eq!(
                next_registration(&mut receiver).await,
                chains(&[ForeignChain::Ethereum])
            );

            // When
            whitelist_sender
                .send(ForeignChainWhitelist::from([
                    (ForeignChain::Ethereum, entry(1)),
                    (ForeignChain::Base, entry(1)),
                ]))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_matches!(receiver.try_recv(), Err(TryRecvError::Empty));
            whitelist_sender
                .send(ForeignChainWhitelist::from([(
                    ForeignChain::Ethereum,
                    entry(2),
                )]))
                .unwrap();

            // Then
            assert_eq!(next_registration(&mut receiver).await, chains(&[]));
        });
        root.await;
    }

    fn series(gauge: &prometheus::IntGaugeVec, chain: ForeignChain) -> Option<i64> {
        gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric().to_vec())
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.get_value() == chain.label())
            })
            .map(|metric| metric.get_gauge().get_value() as i64)
    }

    fn gauges(chain: ForeignChain) -> Option<(i64, i64)> {
        Some((
            series(&metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED, chain)?,
            series(&metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED, chain)?,
        ))
    }

    /// Polygon is whitelisted with quorum 1, Base is configured but not whitelisted. The gauges are
    /// global and reset on publish, so this test needs its own process, as nextest gives it.
    #[test]
    fn publish_rpc_quorum_metrics__should_set_both_gauges_for_the_whitelisted_chains_only() {
        // Given
        let local = ForeignChainsConfig {
            polygon: Some(local_chain()),
            base: Some(local_chain()),
            ..Default::default()
        };
        let whitelist = ForeignChainWhitelist::from([(ForeignChain::Polygon, entry(1))]);

        // When
        publish_rpc_quorum_metrics(&rpc_quorum_statuses(&local, &whitelist));

        // Then
        assert_eq!(gauges(ForeignChain::Polygon), Some((1, 1)));
        assert_eq!(gauges(ForeignChain::Base), None);
    }

    #[test]
    fn publish_rpc_quorum_metrics__should_drop_the_gauges_of_a_chain_that_left_the_whitelist() {
        // Given
        let local = ForeignChainsConfig {
            starknet: Some(local_chain()),
            ..Default::default()
        };
        let whitelist = ForeignChainWhitelist::from([(ForeignChain::Starknet, entry(1))]);
        publish_rpc_quorum_metrics(&rpc_quorum_statuses(&local, &whitelist));

        // When
        publish_rpc_quorum_metrics(&rpc_quorum_statuses(&local, &ForeignChainWhitelist::new()));

        // Then
        assert_eq!(
            series(
                &metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED,
                ForeignChain::Starknet
            ),
            None
        );
        assert_eq!(
            series(
                &metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED,
                ForeignChain::Starknet
            ),
            None
        );
    }
}
