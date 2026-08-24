use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::anyhow;
use mpc_node::keyshare::Keyshare;
use near_mpc_contract_interface::types::{DomainId, EpochId, Keyset, ProtocolContractState};
use tokio_util::sync::CancellationToken;

use crate::keyset::keyset_to_backup;
use crate::ports::{KeyShareRepository, P2PClient};
use near_contract_transport::WatchContractState;

/// Keeps local storage holding the keyshares of the contract's current keyset
pub struct Service<Keyshares, Storage, Contract> {
    keyshares: Keyshares,
    storage: Storage,
    contract_state: Contract,
    retry_delay: Duration,
    backed_up: Option<BackedUpKeyset>,
}

impl<Keyshares, Storage, Contract> Service<Keyshares, Storage, Contract>
where
    Keyshares: P2PClient,
    Storage: KeyShareRepository,
    Contract: WatchContractState<ProtocolContractState>,
    Contract::Error: std::fmt::Debug,
{
    /// Reads back what local storage already holds, so a restart does not re-fetch a keyset
    /// that is already stored.
    pub async fn new(
        keyshares: Keyshares,
        storage: Storage,
        contract_state: Contract,
        retry_delay: Duration,
    ) -> anyhow::Result<Self> {
        let stored = storage
            .load_keyshares()
            .await
            .map_err(|err| anyhow!("failed to load stored keyshares: {err:?}"))?;

        Ok(Self {
            keyshares,
            storage,
            contract_state,
            retry_delay,
            backed_up: BackedUpKeyset::from_keyshares(&stored),
        })
    }

    /// Backs up the observed keyset, then waits for the next one, until `shutdown` is cancelled.
    /// Returns an error if the contract state stops being observed, since that is a failure
    /// rather than a stop that was asked for.
    pub async fn run(mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        tracing::info!(
            backed_up = ?self.backed_up,
            "starting automatic backup service"
        );

        // Armed only after a failed backup: there is work left to re-attempt, and a contract
        // whose state never changes again would otherwise never wake us to do it.
        let mut retry_in = None;

        loop {
            // A read failure is reported by the watcher itself, once per distinct failure
            // rather than once per read, and leaves nothing to back up until a state arrives.
            if let Ok(observed) = self.contract_state.latest() {
                match self.back_up_if_needed(&observed.value, &shutdown).await {
                    Ok(BackupOutcome::BackedUp {
                        epoch_id,
                        num_domains,
                    }) => {
                        retry_in = None;
                        tracing::info!(%epoch_id, num_domains, "backed up keyshares");
                    }
                    Ok(BackupOutcome::Skipped(_)) => retry_in = None,
                    Ok(BackupOutcome::Cancelled) => break,
                    Err(err) => {
                        retry_in = Some(self.retry_delay);
                        tracing::warn!(
                            ?err,
                            retry_in_seconds = self.retry_delay.as_secs(),
                            "keyshare backup failed, retrying"
                        );
                    }
                }
            }

            tokio::select! {
                observed = self.contract_state.changed() => {
                    if let Err(err) = observed {
                        // Not a clean stop: the process should exit non-zero so a supervisor
                        // restarts it.
                        return Err(anyhow!("stopped observing the contract state: {err:?}"));
                    }
                }
                () = sleep_or_pending(retry_in) => {}
                _ = shutdown.cancelled() => break,
            }
        }

        tracing::info!("stopping automatic backup service");
        Ok(())
    }

    /// Backs up keyshares unless local storage already covers `state`'s keyset.
    /// [`Self::backed_up`] is derived from what was stored, not from what was requested, so the
    /// two cannot drift apart.
    async fn back_up_if_needed(
        &mut self,
        state: &ProtocolContractState,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<BackupOutcome> {
        let Ok(keyset) = keyset_to_backup(state) else {
            return Ok(BackupOutcome::Skipped(SkipReason::NoConcludedKeyset));
        };

        if self
            .backed_up
            .as_ref()
            .is_some_and(|backed_up| backed_up.covers(&keyset))
        {
            return Ok(BackupOutcome::Skipped(SkipReason::AlreadyBackedUp {
                contract_epoch_id: keyset.epoch_id,
            }));
        }

        let fetch = self.keyshares.get_keyshares(&keyset);
        let Some(keyshares) = shutdown.run_until_cancelled(fetch).await else {
            return Ok(BackupOutcome::Cancelled);
        };
        let keyshares = keyshares.map_err(|err| anyhow!("keyshare fetch failed: {err:?}"))?;

        self.storage
            .store_keyshares(&keyshares)
            .await
            .map_err(|err| anyhow!("failed to store keyshares: {err:?}"))?;
        self.backed_up = BackedUpKeyset::from_keyshares(&keyshares);
        Ok(BackupOutcome::BackedUp {
            epoch_id: keyset.epoch_id,
            num_domains: keyshares.len(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackupOutcome {
    BackedUp {
        epoch_id: EpochId,
        num_domains: usize,
    },
    Skipped(SkipReason),
    /// Shutdown arrived while waiting on the network.
    Cancelled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    NoConcludedKeyset,
    AlreadyBackedUp { contract_epoch_id: EpochId },
}

/// What the keyshares in local storage cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackedUpKeyset {
    pub epoch_id: EpochId,
    pub domain_ids: BTreeSet<DomainId>,
}

impl BackedUpKeyset {
    /// All keyshares of a stored keyset share its epoch, enforced by
    /// [`PermanentKeyshareData`](mpc_node::keyshare::permanent::PermanentKeyshareData).
    fn from_keyshares(keyshares: &[Keyshare]) -> Option<Self> {
        let first = keyshares.first()?;
        Some(Self {
            epoch_id: first.key_id.epoch_id,
            domain_ids: keyshares
                .iter()
                .map(|keyshare| keyshare.key_id.domain_id)
                .collect(),
        })
    }

    /// Whether a fetch would add nothing. Domains are compared because
    /// `vote_add_domains` extends a keyset without advancing the epoch.
    fn covers(&self, keyset: &Keyset) -> bool {
        match keyset.epoch_id.cmp(&self.epoch_id) {
            Ordering::Greater => false,
            Ordering::Less => true,
            Ordering::Equal => keyset
                .domains
                .iter()
                .all(|domain| self.domain_ids.contains(&domain.domain_id)),
        }
    }
}

/// Sleeps for `delay`, or never returns when there is nothing to retry.
async fn sleep_or_pending(delay: Option<Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    use mpc_node::keyshare::Keyshare;
    use mpc_node::keyshare::test_utils::generate_dummy_keyshare;
    use near_contract_transport::{ObservedState, TransportError};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rstest::rstest;
    use tokio::sync::{Mutex, Notify, watch};
    use tokio::time::timeout;

    use crate::test_utils::{
        fixture_epoch_id, initializing_state, resharing_state, running_state_with_epoch,
        running_state_without_domains,
    };

    const FIXTURE_DOMAIN_IDS: [u64; 2] = [0, 1];
    /// Only the retry test waits it out, and it does so under a paused clock.
    const TEST_RETRY_DELAY: Duration = Duration::from_secs(60);

    type TestService = Service<FakeP2PClient, FakeKeyshareStorage, FakeWatchContractState>;

    struct FakeP2PClient {
        get_keyshares_calls: AtomicUsize,
        fetched: Arc<Notify>,
        /// Domains the node holds, or all domains of the requested keyset when `None`.
        held_domain_ids: Option<Vec<u64>>,
        fail: bool,
        hang: bool,
    }

    impl FakeP2PClient {
        fn new() -> Self {
            Self {
                get_keyshares_calls: AtomicUsize::new(0),
                fetched: Arc::new(Notify::new()),
                held_domain_ids: None,
                fail: false,
                hang: false,
            }
        }

        fn holding_domains(domain_ids: &[u64]) -> Self {
            Self {
                held_domain_ids: Some(domain_ids.to_vec()),
                ..Self::new()
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::new()
            }
        }

        /// Accepts the fetch and never answers it.
        fn hanging() -> Self {
            Self {
                hang: true,
                ..Self::new()
            }
        }

        fn get_keyshares_calls(&self) -> usize {
            self.get_keyshares_calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl P2PClient for FakeP2PClient {
        type Error = anyhow::Error;

        async fn get_keyshares(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
            self.get_keyshares_calls
                .fetch_add(1, AtomicOrdering::SeqCst);
            self.fetched.notify_one();
            if self.hang {
                std::future::pending::<()>().await;
            }
            if self.fail {
                anyhow::bail!("mpc node is unreachable");
            }
            let domain_ids = self.held_domain_ids.clone().unwrap_or_else(|| {
                keyset
                    .domains
                    .iter()
                    .map(|domain| domain.domain_id.0)
                    .collect()
            });
            Ok(keyshares_for(keyset.epoch_id.get(), &domain_ids))
        }

        async fn put_keyshares(&self, _keyshares: &[Keyshare]) -> Result<(), Self::Error> {
            unreachable!("the automatic backup service never pushes keyshares")
        }
    }

    struct FakeKeyshareStorage {
        keyshares: Mutex<Vec<Keyshare>>,
        fail_load_after_store: bool,
        stored: Arc<AtomicUsize>,
        stored_notify: Arc<Notify>,
    }

    impl FakeKeyshareStorage {
        fn empty() -> Self {
            Self::with_keyshares(vec![])
        }

        fn with_keyshares(keyshares: Vec<Keyshare>) -> Self {
            Self {
                keyshares: Mutex::new(keyshares),
                fail_load_after_store: false,
                stored: Arc::new(AtomicUsize::new(0)),
                stored_notify: Arc::new(Notify::new()),
            }
        }

        fn failing_load_after_store() -> Self {
            Self {
                fail_load_after_store: true,
                ..Self::empty()
            }
        }
    }

    impl KeyShareRepository for FakeKeyshareStorage {
        type Error = anyhow::Error;

        async fn store_keyshares(&self, keyshares: &[Keyshare]) -> Result<(), Self::Error> {
            *self.keyshares.lock().await = keyshares.to_vec();
            self.stored.fetch_add(1, AtomicOrdering::SeqCst);
            // `notify_one` stores a permit, so a waiter that registers late still observes it.
            self.stored_notify.notify_one();
            Ok(())
        }

        async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
            if self.fail_load_after_store && self.stored.load(AtomicOrdering::SeqCst) > 0 {
                anyhow::bail!("storage is unreadable");
            }
            Ok(self.keyshares.lock().await.clone())
        }
    }

    /// No assertion depends on the observation height.
    const FAKE_OBSERVED_AT: u64 = 0;

    struct FakeWatchContractState {
        states: watch::Receiver<Result<ProtocolContractState, &'static str>>,
    }

    impl FakeWatchContractState {
        fn observing(
            state: ProtocolContractState,
        ) -> (
            watch::Sender<Result<ProtocolContractState, &'static str>>,
            Self,
        ) {
            let (sender, states) = watch::channel(Ok(state));
            (sender, Self { states })
        }

        /// For tests that never read the contract state.
        fn unused() -> Self {
            Self::observing(running_state_with_epoch(0)).1
        }
    }

    impl WatchContractState<ProtocolContractState> for FakeWatchContractState {
        type Error = &'static str;

        fn latest(
            &mut self,
        ) -> Result<ObservedState<ProtocolContractState>, TransportError<Self::Error>> {
            self.states
                .borrow_and_update()
                .clone()
                .map(|value| ObservedState {
                    observed_at: FAKE_OBSERVED_AT.into(),
                    value,
                })
                .map_err(TransportError::ViewError)
        }

        async fn changed(&mut self) -> Result<(), TransportError<Self::Error>> {
            self.states
                .changed()
                .await
                .map_err(|_| TransportError::MonitoringClosed)
        }
    }

    fn keyshares_for(epoch_id: u64, domain_ids: &[u64]) -> Vec<Keyshare> {
        let mut rng = StdRng::seed_from_u64(42);
        domain_ids
            .iter()
            .map(|domain_id| generate_dummy_keyshare(epoch_id, *domain_id, 1, &mut rng))
            .collect()
    }

    fn backed_up(epoch_id: u64, domain_ids: &[u64]) -> Option<BackedUpKeyset> {
        Some(BackedUpKeyset {
            epoch_id: EpochId::new(epoch_id),
            domain_ids: domain_ids.iter().copied().map(DomainId).collect(),
        })
    }

    async fn service(keyshares: FakeP2PClient, storage: FakeKeyshareStorage) -> TestService {
        service_watching(keyshares, storage, FakeWatchContractState::unused()).await
    }

    async fn service_watching(
        keyshares: FakeP2PClient,
        storage: FakeKeyshareStorage,
        contract_state: FakeWatchContractState,
    ) -> TestService {
        Service::new(keyshares, storage, contract_state, TEST_RETRY_DELAY)
            .await
            .expect("the service should read local storage on startup")
    }

    async fn must_back_up_if_needed(
        service: &mut TestService,
        state: &ProtocolContractState,
    ) -> BackupOutcome {
        service
            .back_up_if_needed(state, &CancellationToken::new())
            .await
            .expect("the backup should succeed")
    }

    #[tokio::test]
    async fn back_up_if_needed__should_back_up_when_nothing_is_stored() {
        // Given
        let mut service = service(FakeP2PClient::new(), FakeKeyshareStorage::empty()).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: EpochId::new(5),
                num_domains: 2
            }
        );
        assert_eq!(service.backed_up, backed_up(5, &FIXTURE_DOMAIN_IDS));
        let stored = service.storage.load_keyshares().await.unwrap();
        assert_eq!(stored, keyshares_for(5, &FIXTURE_DOMAIN_IDS));
    }

    #[tokio::test]
    async fn back_up_if_needed__should_back_up_when_epoch_advances() {
        // Given
        let storage = FakeKeyshareStorage::with_keyshares(keyshares_for(5, &FIXTURE_DOMAIN_IDS));
        let mut service = service(FakeP2PClient::new(), storage).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(6)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: EpochId::new(6),
                num_domains: 2
            }
        );
        assert_eq!(service.backed_up, backed_up(6, &FIXTURE_DOMAIN_IDS));
        assert_eq!(service.keyshares.get_keyshares_calls(), 1);
    }

    #[tokio::test]
    async fn back_up_if_needed__should_back_up_when_keyset_gains_a_domain_in_the_same_epoch() {
        // Given
        let storage = FakeKeyshareStorage::with_keyshares(keyshares_for(5, &[0]));
        let mut service = service(FakeP2PClient::new(), storage).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: EpochId::new(5),
                num_domains: 2
            }
        );
        assert_eq!(service.backed_up, backed_up(5, &FIXTURE_DOMAIN_IDS));
    }

    #[tokio::test]
    async fn back_up_if_needed__should_skip_when_stored_keyshares_cover_the_keyset() {
        // Given
        let stored = keyshares_for(5, &FIXTURE_DOMAIN_IDS);
        let storage = FakeKeyshareStorage::with_keyshares(stored.clone());
        let mut service = service(FakeP2PClient::new(), storage).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::Skipped(SkipReason::AlreadyBackedUp {
                contract_epoch_id: EpochId::new(5)
            })
        );
        assert_eq!(service.keyshares.get_keyshares_calls(), 0);
        assert_eq!(service.storage.load_keyshares().await.unwrap(), stored);
    }

    #[tokio::test]
    async fn back_up_if_needed__should_skip_when_stored_epoch_is_newer() {
        // Given
        let storage = FakeKeyshareStorage::with_keyshares(keyshares_for(6, &FIXTURE_DOMAIN_IDS));
        let mut service = service(FakeP2PClient::new(), storage).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::Skipped(SkipReason::AlreadyBackedUp {
                contract_epoch_id: EpochId::new(5)
            })
        );
        assert_eq!(service.keyshares.get_keyshares_calls(), 0);
        assert_eq!(service.backed_up, backed_up(6, &FIXTURE_DOMAIN_IDS));
    }

    #[tokio::test]
    async fn back_up_if_needed__should_back_up_the_previous_keyset_while_resharing() {
        // Given
        let mut service = service(FakeP2PClient::new(), FakeKeyshareStorage::empty()).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &resharing_state()).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: fixture_epoch_id(),
                num_domains: 2
            }
        );
        assert_eq!(
            service.backed_up,
            backed_up(fixture_epoch_id().get(), &FIXTURE_DOMAIN_IDS)
        );
    }

    #[rstest]
    #[case::not_initialized(ProtocolContractState::NotInitialized)]
    #[case::initializing(initializing_state())]
    #[case::running_without_domains(running_state_without_domains())]
    #[tokio::test]
    async fn back_up_if_needed__should_skip_when_contract_has_no_concluded_keyset(
        #[case] contract_state: ProtocolContractState,
    ) {
        // Given
        let mut service = service(FakeP2PClient::new(), FakeKeyshareStorage::empty()).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &contract_state).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::Skipped(SkipReason::NoConcludedKeyset)
        );
        assert_eq!(service.keyshares.get_keyshares_calls(), 0);
        assert_eq!(service.backed_up, None);
    }

    #[tokio::test]
    async fn back_up_if_needed__should_keep_tracked_keyset_when_fetch_fails() {
        // Given
        let mut service = service(FakeP2PClient::failing(), FakeKeyshareStorage::empty()).await;

        // When
        let result = service
            .back_up_if_needed(&running_state_with_epoch(5), &CancellationToken::new())
            .await;

        // Then
        result.expect_err("a failed fetch should fail the tick");
        assert_eq!(service.backed_up, None);
        assert!(service.storage.load_keyshares().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn back_up_if_needed__should_track_only_the_domains_the_node_returned() {
        // Given
        let mut service = service(
            FakeP2PClient::holding_domains(&[0]),
            FakeKeyshareStorage::empty(),
        )
        .await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: EpochId::new(5),
                num_domains: 1
            }
        );
        assert_eq!(service.backed_up, backed_up(5, &[0]));
    }

    #[tokio::test]
    async fn back_up_if_needed__should_advance_tracked_keyset_when_storage_read_fails_after_store()
    {
        // Given
        let storage = FakeKeyshareStorage::failing_load_after_store();
        let mut service = service(FakeP2PClient::new(), storage).await;

        // When
        let outcome = must_back_up_if_needed(&mut service, &running_state_with_epoch(5)).await;

        // Then
        assert_eq!(
            outcome,
            BackupOutcome::BackedUp {
                epoch_id: EpochId::new(5),
                num_domains: 2
            }
        );
        assert_eq!(service.backed_up, backed_up(5, &FIXTURE_DOMAIN_IDS));
    }

    #[tokio::test]
    async fn back_up_if_needed__should_report_cancellation_when_shutdown_arrives_during_a_fetch() {
        // Given
        let mut service = service(FakeP2PClient::hanging(), FakeKeyshareStorage::empty()).await;
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        // When
        let outcome = service
            .back_up_if_needed(&running_state_with_epoch(5), &shutdown)
            .await
            .expect("a cancelled fetch is not a failure");

        // Then
        assert_eq!(outcome, BackupOutcome::Cancelled);
        assert_eq!(service.backed_up, None);
        assert!(service.storage.load_keyshares().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn service_run__should_back_up_the_observed_state_before_waiting_for_a_change() {
        // Given a watcher that never reports a change, so only acting before the wait can
        // produce a backup. `_sender` is held precisely so `changed()` stays pending.
        let (_sender, contract_state) =
            FakeWatchContractState::observing(running_state_with_epoch(5));
        let storage = FakeKeyshareStorage::empty();
        let stored = storage.stored.clone();
        let stored_notify = storage.stored_notify.clone();
        let service = service_watching(FakeP2PClient::new(), storage, contract_state).await;
        let shutdown = CancellationToken::new();

        // When
        let stop_after_the_first_backup = async {
            stored_notify.notified().await;
            shutdown.cancel();
        };
        let (result, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(service.run(shutdown.clone()), stop_after_the_first_backup)
        })
        .await
        .expect("the observed state should be backed up without waiting for a change");

        // Then
        result.expect("the service should return Ok on shutdown");
        assert_eq!(stored.load(AtomicOrdering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn service_run__should_retry_a_failed_backup_after_the_retry_delay() {
        // Given
        let (_sender, contract_state) =
            FakeWatchContractState::observing(running_state_with_epoch(5));
        let mpc_p2p_client = FakeP2PClient::failing();
        let fetched = mpc_p2p_client.fetched.clone();
        let service =
            service_watching(mpc_p2p_client, FakeKeyshareStorage::empty(), contract_state).await;
        let shutdown = CancellationToken::new();

        // When the observed state never changes, only the retry timer can drive a second attempt.
        let await_a_retry = async {
            fetched.notified().await;
            fetched.notified().await;
            shutdown.cancel();
        };
        // The guard has to outlast the retry delay: with the clock paused, tokio advances to
        // whichever deadline comes first.
        let (result, ()) = timeout(TEST_RETRY_DELAY * 10, async {
            tokio::join!(service.run(shutdown.clone()), await_a_retry)
        })
        .await
        .expect("the failed backup should be re-attempted without a state change");

        // Then
        result.expect("the service should return Ok on shutdown");
    }

    #[tokio::test]
    async fn service_run__should_back_up_a_newly_observed_state() {
        // Given
        let stored = keyshares_for(5, &FIXTURE_DOMAIN_IDS);
        let (sender, contract_state) =
            FakeWatchContractState::observing(running_state_with_epoch(5));
        let storage = FakeKeyshareStorage::with_keyshares(stored.clone());
        let stored_notify = storage.stored_notify.clone();
        let service = service_watching(FakeP2PClient::new(), storage, contract_state).await;
        let shutdown = CancellationToken::new();

        // When
        let observe_a_resharing = async {
            sender
                .send(Ok(running_state_with_epoch(6)))
                .expect("the service should still be listening");
            stored_notify.notified().await;
            shutdown.cancel();
        };
        let (result, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(service.run(shutdown.clone()), observe_a_resharing)
        })
        .await
        .expect("the service should back up the new state and then stop");

        // Then
        result.expect("the service should return Ok on shutdown");
    }

    #[tokio::test]
    async fn service_run__should_fail_when_the_contract_state_is_no_longer_observed() {
        // Given
        let (sender, contract_state) =
            FakeWatchContractState::observing(running_state_with_epoch(5));
        let service = service_watching(
            FakeP2PClient::new(),
            FakeKeyshareStorage::empty(),
            contract_state,
        )
        .await;

        // When
        drop(sender);

        // Then
        let result = timeout(
            Duration::from_secs(5),
            service.run(CancellationToken::new()),
        )
        .await
        .expect("the service should stop once nothing observes the contract state");

        let err = result.expect_err("losing the watcher is a failure, not a clean stop");
        assert!(
            err.to_string().contains("stopped observing"),
            "unexpected error: {err:?}"
        );
    }
}
