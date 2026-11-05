//! Registers on the contract the foreign chains this node can serve, and keeps that registration
//! in step with the whitelist and with what the contract records.

use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::pin::Pin;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use mpc_node_config::ForeignChainsConfig;
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;
use tokio::time::Sleep;

use crate::foreign_chain_rpc_policy::{RpcQuorumStatus, eligible_chains, rpc_quorum_statuses};
use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::indexer::tx_sender::{TransactionProcessorError, TransactionSender};
use crate::indexer::types::ChainSendTransactionRequest;
use crate::metrics;
use crate::tracking::{self, AutoAbortTask};

const MIN_RESEND_DELAY: Duration = Duration::from_secs(30);
const MAX_RESEND_DELAY: Duration = Duration::from_hours(1);

/// Registers the eligible chains on start, then until the contract records them for `my_tls_key`,
/// and again whenever the recorded chains stop matching the eligible ones.
/// Must be called from a tracked task. Dropping the returned task stops the registrar.
pub(crate) fn spawn_foreign_chains_registrar(
    txn_sender: impl TransactionSender + 'static,
    whitelist: watch::Receiver<ForeignChainWhitelist>,
    registered: watch::Receiver<dtos::ForeignChainsConfigs>,
    my_tls_key: dtos::Ed25519PublicKey,
    local: ForeignChainsConfig,
) -> AutoAbortTask<()> {
    tracking::spawn(
        "foreign chains registrar",
        keep_foreign_chains_registration_up_to_date(
            txn_sender, whitelist, registered, my_tls_key, local,
        ),
    )
}

fn resend_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(MIN_RESEND_DELAY)
        .with_max_delay(MAX_RESEND_DELAY)
        .without_max_times()
}

/// Resends a registration that has not landed after each delay of [`resend_backoff`], which
/// restarts when a registration lands or the eligible chains change. Returns once the transaction
/// processor or a watched channel closes.
async fn keep_foreign_chains_registration_up_to_date(
    txn_sender: impl TransactionSender,
    mut whitelist: watch::Receiver<ForeignChainWhitelist>,
    mut registered: watch::Receiver<dtos::ForeignChainsConfigs>,
    my_tls_key: dtos::Ed25519PublicKey,
    local: ForeignChainsConfig,
) {
    let mut pending: Option<PendingRegistration> = None;
    let mut last_published: Option<BTreeMap<dtos::ForeignChain, RpcQuorumStatus>> = None;
    // Keygen does not make the contract recompute the available chains, but a registration does.
    // So send once per start, even if the contract already records the eligible chains.
    let mut is_start = true;
    loop {
        let is_first_pass = mem::take(&mut is_start);
        let statuses = rpc_quorum_statuses(&local, &whitelist.borrow_and_update());
        if last_published.as_ref() != Some(&statuses) {
            publish_rpc_quorum_metrics(&statuses);
        }
        let eligible = eligible_chains(&statuses);
        last_published = Some(statuses);
        let is_registered = registered
            .borrow_and_update()
            .get(&my_tls_key)
            .is_some_and(|recorded| **recorded == eligible);
        let sent = if is_first_pass && is_registered {
            tracing::info!(
                chains = ?eligible,
                "registering the foreign chains this node can serve, which the contract already records"
            );
            register_foreign_chains(&txn_sender, &eligible).await
        } else {
            update_registration(&mut pending, is_registered, eligible, &txn_sender).await
        };
        match sent {
            Ok(()) => {}
            Err(TransactionProcessorError::ProcessorIsClosed) => break,
        }
        tokio::select! {
            changed = whitelist.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            changed = registered.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            () = wait_for_resend(&mut pending) => {}
        }
    }
}

async fn update_registration(
    pending: &mut Option<PendingRegistration>,
    is_registered: bool,
    eligible: BTreeSet<dtos::ForeignChain>,
    txn_sender: &impl TransactionSender,
) -> Result<(), TransactionProcessorError> {
    if is_registered {
        *pending = None;
    } else if let Some(registration) = pending
        && registration.chains == eligible
    {
        registration.resend_if_due(txn_sender).await?;
    } else {
        *pending = Some(PendingRegistration::send(txn_sender, eligible).await?);
    }
    Ok(())
}

struct PendingRegistration {
    chains: BTreeSet<dtos::ForeignChain>,
    resends: u32,
    resend_delays: ExponentialBackoff,
    resend_timer: Pin<Box<Sleep>>,
}

impl PendingRegistration {
    async fn send(
        txn_sender: &impl TransactionSender,
        chains: BTreeSet<dtos::ForeignChain>,
    ) -> Result<Self, TransactionProcessorError> {
        tracing::info!(
            ?chains,
            "registering the foreign chains this node can serve"
        );
        register_foreign_chains(txn_sender, &chains).await?;
        let mut resend_delays = resend_backoff().build();
        let delay = resend_delays.next().unwrap_or(MAX_RESEND_DELAY);
        Ok(Self {
            chains,
            resends: 0,
            resend_delays,
            resend_timer: Box::pin(tokio::time::sleep(delay)),
        })
    }

    async fn resend_if_due(
        &mut self,
        txn_sender: &impl TransactionSender,
    ) -> Result<(), TransactionProcessorError> {
        if self.resend_timer.deadline() > tokio::time::Instant::now() {
            return Ok(());
        }
        self.resends = self.resends.saturating_add(1);
        let delay = self.resend_delays.next().unwrap_or(MAX_RESEND_DELAY);
        tracing::warn!(
            chains = ?self.chains,
            resends = self.resends,
            next_resend_in = ?delay,
            "foreign chains registration has not landed, resending; check that the node's access \
             key allows register_foreign_chains_config"
        );
        register_foreign_chains(txn_sender, &self.chains).await?;
        self.resend_timer = Box::pin(tokio::time::sleep(delay));
        Ok(())
    }
}

/// Never completes while nothing is pending.
async fn wait_for_resend(pending: &mut Option<PendingRegistration>) {
    match pending {
        Some(pending) => pending.resend_timer.as_mut().await,
        None => std::future::pending().await,
    }
}

/// An empty set is still sent, so the contract drops this node as a supporter of every chain.
async fn register_foreign_chains(
    txn_sender: &impl TransactionSender,
    chains: &BTreeSet<dtos::ForeignChain>,
) -> Result<(), TransactionProcessorError> {
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

    fn my_tls_key() -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([1; 32])
    }

    fn recorded(my_chains: &[ForeignChain]) -> dtos::ForeignChainsConfigs {
        BTreeMap::from([(my_tls_key(), chains(my_chains))]).into()
    }

    fn ethereum_whitelist(quorum: u64) -> ForeignChainWhitelist {
        ForeignChainWhitelist::from([(ForeignChain::Ethereum, entry(quorum))])
    }

    fn ethereum() -> dtos::ForeignChainsConfig {
        chains(&[ForeignChain::Ethereum])
    }

    const IMMEDIATELY: Duration = Duration::ZERO;

    struct Registrar {
        whitelist: watch::Sender<ForeignChainWhitelist>,
        registered: watch::Sender<dtos::ForeignChainsConfigs>,
        transactions: mpsc::Receiver<ChainSendTransactionRequest>,
        _task: AutoAbortTask<()>,
    }

    /// Tests run in paused time, so a wait lasts exactly until the earliest timer.
    impl Registrar {
        /// Ethereum is configured locally.
        fn start(whitelist: ForeignChainWhitelist, registered: dtos::ForeignChainsConfigs) -> Self {
            let local = ForeignChainsConfig {
                ethereum: Some(local_chain()),
                ..Default::default()
            };
            let (whitelist, whitelist_receiver) = watch::channel(whitelist);
            let (registered, registered_receiver) = watch::channel(registered);
            let (sender, transactions) = mpsc::channel(10);
            let task = tracking::spawn(
                "registrar under test",
                keep_foreign_chains_registration_up_to_date(
                    MockTransactionSender {
                        transaction_sender: sender,
                    },
                    whitelist_receiver,
                    registered_receiver,
                    my_tls_key(),
                    local,
                ),
            );
            Self {
                whitelist,
                registered,
                transactions,
                _task: task,
            }
        }

        /// Returns the next registration and how long it took to come.
        async fn next_registration(&mut self) -> (dtos::ForeignChainsConfig, Duration) {
            let started = tokio::time::Instant::now();
            let request = tokio::time::timeout(MAX_RESEND_DELAY * 2, self.transactions.recv())
                .await
                .expect("timed out waiting for a registration")
                .expect("transaction sender dropped");
            (registered_chains(request), started.elapsed())
        }

        async fn assert_no_registration_for(&mut self, duration: Duration) {
            let received = tokio::time::timeout(duration, self.transactions.recv()).await;
            assert_matches!(received, Err(_));
        }
    }

    /// Ethereum is configured and whitelisted with a reachable quorum.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_register_the_eligible_chains_on_start()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let whitelist = ethereum_whitelist(1);

            // When
            let mut registrar = Registrar::start(whitelist, dtos::ForeignChainsConfigs::default());

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_register_once_on_start_when_the_contract_already_records_the_chains()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let whitelist = ethereum_whitelist(1);

            // When
            let mut registrar = Registrar::start(whitelist, recorded(&[ForeignChain::Ethereum]));

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            registrar
                .assert_no_registration_for(MAX_RESEND_DELAY * 2)
                .await;
        });
        root.await;
    }

    /// Ethereum is configured but not whitelisted at start. The whitelist then makes it eligible.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_reregister_when_the_eligible_chains_change()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(
                ForeignChainWhitelist::new(),
                dtos::ForeignChainsConfigs::default(),
            );
            assert_eq!(
                registrar.next_registration().await,
                (chains(&[]), IMMEDIATELY)
            );

            // When
            registrar.whitelist.send(ethereum_whitelist(1)).unwrap();

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
        });
        root.await;
    }

    /// Ethereum is sent but has not landed. Whitelisting a chain this node does not run
    /// changes nothing, so no registration follows. Raising Ethereum's quorum out of reach then
    /// registers an empty set.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_skip_a_whitelist_change_that_keeps_the_eligible_chains()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            registrar
                .whitelist
                .send(ForeignChainWhitelist::from([
                    (ForeignChain::Ethereum, entry(1)),
                    (ForeignChain::Base, entry(1)),
                ]))
                .unwrap();
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;
            registrar.whitelist.send(ethereum_whitelist(2)).unwrap();

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (chains(&[]), IMMEDIATELY)
            );
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_resend_a_registration_that_has_not_landed()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (ethereum(), MIN_RESEND_DELAY));
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_not_resend_before_the_resend_delay()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            let almost_due = MIN_RESEND_DELAY - Duration::from_millis(1);

            // Then
            registrar.assert_no_registration_for(almost_due).await;
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_stop_resending_once_the_registration_lands()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            registrar
                .registered
                .send(recorded(&[ForeignChain::Ethereum]))
                .unwrap();

            // Then
            registrar
                .assert_no_registration_for(MAX_RESEND_DELAY * 2)
                .await;
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_stop_once_the_transaction_processor_closes()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            drop(registrar.transactions);

            // Then
            let stopped =
                tokio::time::timeout(MIN_RESEND_DELAY * 2, registrar.whitelist.closed()).await;
            assert_matches!(stopped, Ok(()));
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_wait_longer_after_a_resend_that_has_not_landed()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), MIN_RESEND_DELAY)
            );

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (ethereum(), MIN_RESEND_DELAY * 2));
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_cap_the_resend_wait() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            let mut delay = MIN_RESEND_DELAY;
            while delay < MAX_RESEND_DELAY {
                assert_eq!(registrar.next_registration().await, (ethereum(), delay));
                delay *= 2;
            }

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (ethereum(), MAX_RESEND_DELAY));
        });
        root.await;
    }

    /// A resend doubles the wait. The registration then lands, and the contract later loses it.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_reset_the_resend_wait_once_a_registration_lands()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), MIN_RESEND_DELAY)
            );
            registrar
                .registered
                .send(recorded(&[ForeignChain::Ethereum]))
                .unwrap();
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;
            registrar
                .registered
                .send(dtos::ForeignChainsConfigs::default())
                .unwrap();
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (ethereum(), MIN_RESEND_DELAY));
        });
        root.await;
    }

    /// A resend doubles the wait. Raising Ethereum's quorum out of reach then makes the empty set
    /// eligible.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_reset_the_resend_wait_when_the_eligible_chains_change()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), dtos::ForeignChainsConfigs::default());
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), MIN_RESEND_DELAY)
            );
            registrar.whitelist.send(ethereum_whitelist(2)).unwrap();
            assert_eq!(
                registrar.next_registration().await,
                (chains(&[]), IMMEDIATELY)
            );

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (chains(&[]), MIN_RESEND_DELAY));
        });
        root.await;
    }

    /// Each round flips Ethereum's eligibility and drops the record in one go, before the
    /// registrar runs. Which ready branch `select!` takes is random, so many rounds make a stale
    /// registration show up.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_register_the_new_eligible_chains_when_the_record_changes_with_the_whitelist()
     {
        const ROUNDS: usize = 100;
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), recorded(&[ForeignChain::Ethereum]));
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;

            for round in 0..ROUNDS {
                let (quorum, eligible): (u64, &[ForeignChain]) = if round % 2 == 0 {
                    (2, &[])
                } else {
                    (1, &[ForeignChain::Ethereum])
                };

                // When
                registrar
                    .whitelist
                    .send(ethereum_whitelist(quorum))
                    .unwrap();
                registrar
                    .registered
                    .send(dtos::ForeignChainsConfigs::default())
                    .unwrap();

                // Then
                assert_eq!(
                    registrar.next_registration().await,
                    (chains(eligible), IMMEDIATELY),
                    "round {round}"
                );
                registrar.registered.send(recorded(eligible)).unwrap();
                registrar
                    .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                    .await;
            }
        });
        root.await;
    }

    /// The contract records Ethereum, then loses the record, as after a state migration.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_reregister_at_once_when_the_contract_loses_the_registration()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), recorded(&[ForeignChain::Ethereum]));
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;

            // When
            registrar
                .registered
                .send(dtos::ForeignChainsConfigs::default())
                .unwrap();

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
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
                    .any(|label| label.value() == chain.label())
            })
            .map(|metric| metric.get_gauge().get_value() as i64)
    }

    fn gauges(chain: ForeignChain) -> Option<(i64, i64)> {
        Some((
            series(&metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED, chain)?,
            series(&metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED, chain)?,
        ))
    }

    /// The gauges are cleared after the first publish. A recorded-config change then wakes the
    /// registrar without changing the RPC quorum statuses. The gauges are global, so this test
    /// needs its own process, as nextest gives it.
    #[tokio::test(start_paused = true)]
    async fn keep_foreign_chains_registration_up_to_date__should_publish_rpc_quorum_metrics_only_when_they_change()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar =
                Registrar::start(ethereum_whitelist(1), recorded(&[ForeignChain::Ethereum]));
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;
            assert_eq!(gauges(ForeignChain::Ethereum), Some((1, 1)));
            metrics::MPC_FOREIGN_CHAIN_RPC_QUORUM_REQUIRED.reset();
            metrics::MPC_FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED.reset();

            // When
            registrar
                .registered
                .send(dtos::ForeignChainsConfigs::default())
                .unwrap();
            assert_eq!(
                registrar.next_registration().await,
                (ethereum(), IMMEDIATELY)
            );

            // Then
            assert_eq!(gauges(ForeignChain::Ethereum), None);
        });
        root.await;
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
