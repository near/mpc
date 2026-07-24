use std::time::Duration;

use near_mpc_contract_interface::types::{EpochId, Keyset, ProtocolContractState};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::backup::fetch_and_store;
use crate::ports::{ContractStateReader, KeyShareRepository, P2PClient};

#[derive(Debug, PartialEq, Eq)]
pub enum TickOutcome {
    BackedUp(EpochId),
    Skipped(SkipReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    NotBackupState,
    AlreadyCurrent(EpochId),
}

/// Only `Running` carries a concluded keyset; initializing/resharing epochs aren't final
/// until the contract returns to `Running`, so they yield `None`.
pub fn keyset_to_backup(state: &ProtocolContractState) -> Option<Keyset> {
    match state {
        ProtocolContractState::Running(state) => Some(state.keyset.clone()),
        ProtocolContractState::Initializing(_)
        | ProtocolContractState::Resharing(_)
        | ProtocolContractState::NotInitialized => None,
    }
}

/// Backs up keyshares if the epoch has advanced past `last_epoch`, updating it on success.
pub async fn backup_tick(
    p2p: &impl P2PClient,
    storage: &impl KeyShareRepository,
    contract: &impl ContractStateReader,
    last_epoch: &mut Option<EpochId>,
) -> anyhow::Result<TickOutcome> {
    let state = contract
        .get_contract_state()
        .await
        .map_err(|err| anyhow::anyhow!("could not get contract state: {err:?}"))?;

    let Some(keyset) = keyset_to_backup(&state) else {
        return Ok(TickOutcome::Skipped(SkipReason::NotBackupState));
    };

    let epoch = keyset.epoch_id;
    let is_new_epoch = last_epoch.is_none_or(|last| epoch.get() > last.get());
    if !is_new_epoch {
        return Ok(TickOutcome::Skipped(SkipReason::AlreadyCurrent(epoch)));
    }

    fetch_and_store(p2p, storage, &keyset).await?;
    *last_epoch = Some(epoch);
    Ok(TickOutcome::BackedUp(epoch))
}

/// Runs the automatic backup service until `shutdown` is cancelled. The starting epoch is
/// derived from stored keyshares so a restart does not re-fetch an already-backed-up epoch.
pub async fn run_service(
    p2p: &impl P2PClient,
    storage: &impl KeyShareRepository,
    contract: &impl ContractStateReader,
    poll_interval: Duration,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut last_epoch = stored_epoch(storage).await?;
    tracing::info!(
        last_epoch = last_epoch.map(|e| e.get()),
        poll_interval_seconds = poll_interval.as_secs(),
        "starting automatic backup service"
    );

    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match backup_tick(p2p, storage, contract, &mut last_epoch).await {
                    Ok(TickOutcome::BackedUp(epoch)) => {
                        tracing::info!(epoch = epoch.get(), "backed up keyshares for new epoch");
                    }
                    Ok(TickOutcome::Skipped(reason)) => {
                        tracing::debug!(?reason, "no backup needed");
                    }
                    Err(err) => {
                        tracing::warn!(?err, "backup attempt failed; will retry next tick");
                    }
                }
            }
            _ = shutdown.cancelled() => {
                tracing::info!("shutdown requested, stopping automatic backup service");
                return Ok(());
            }
        }
    }
}

async fn stored_epoch(storage: &impl KeyShareRepository) -> anyhow::Result<Option<EpochId>> {
    let keyshares = storage
        .load_keyshares()
        .await
        .map_err(|err| anyhow::anyhow!("failed to load existing keyshares: {err:?}"))?;
    Ok(keyshares.first().map(|keyshare| keyshare.key_id.epoch_id))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mpc_node::keyshare::Keyshare;
    use mpc_node::keyshare::test_utils::generate_dummy_keyshare;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tokio::sync::Mutex;

    use super::*;

    const RUNNING_FIXTURE: &str = include_str!("../assets/contract_state.json");

    fn running_state_with_epoch(epoch: u64) -> ProtocolContractState {
        let mut state: ProtocolContractState = serde_json::from_str(RUNNING_FIXTURE).unwrap();
        let ProtocolContractState::Running(ref mut running) = state else {
            panic!("fixture is expected to be a Running state");
        };
        running.keyset.epoch_id = EpochId::new(epoch);
        state
    }

    struct FakeP2p {
        get_calls: AtomicUsize,
    }

    impl FakeP2p {
        fn new() -> Self {
            Self {
                get_calls: AtomicUsize::new(0),
            }
        }
    }

    impl P2PClient for FakeP2p {
        type Error = anyhow::Error;

        async fn get_keyshares(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            let epoch = keyset.epoch_id.get();
            let mut rng = StdRng::seed_from_u64(epoch);
            let keyshares = (0..keyset.domains.len())
                .map(|domain| generate_dummy_keyshare(epoch, domain as u64, 1, &mut rng))
                .collect();
            Ok(keyshares)
        }

        async fn put_keyshares(&self, _keyshares: &[Keyshare]) -> Result<(), Self::Error> {
            unreachable!("automatic backup service never pushes keyshares")
        }
    }

    struct FakeStorage {
        stored: Mutex<Vec<Keyshare>>,
    }

    impl FakeStorage {
        fn empty() -> Self {
            Self {
                stored: Mutex::new(vec![]),
            }
        }
    }

    impl KeyShareRepository for FakeStorage {
        type Error = anyhow::Error;

        async fn store_keyshares(&self, keyshares: &[Keyshare]) -> Result<(), Self::Error> {
            *self.stored.lock().await = keyshares.to_vec();
            Ok(())
        }

        async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
            Ok(self.stored.lock().await.clone())
        }
    }

    struct FakeContract {
        state: ProtocolContractState,
    }

    impl ContractStateReader for FakeContract {
        type Error = anyhow::Error;

        async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
            Ok(self.state.clone())
        }
    }

    #[test]
    fn keyset_to_backup__should_return_keyset_for_running_state() {
        // Given
        let state = running_state_with_epoch(5);

        // When
        let keyset = keyset_to_backup(&state);

        // Then
        assert_eq!(keyset.map(|k| k.epoch_id.get()), Some(5));
    }

    #[test]
    fn keyset_to_backup__should_return_none_when_not_initialized() {
        // Given
        let state = ProtocolContractState::NotInitialized;

        // When
        let keyset = keyset_to_backup(&state);

        // Then
        assert_eq!(keyset, None);
    }

    #[tokio::test]
    async fn backup_tick__should_back_up_when_epoch_is_new() {
        // Given
        let p2p = FakeP2p::new();
        let storage = FakeStorage::empty();
        let contract = FakeContract {
            state: running_state_with_epoch(5),
        };
        let mut last_epoch = None;

        // When
        let outcome = backup_tick(&p2p, &storage, &contract, &mut last_epoch)
            .await
            .unwrap();

        // Then
        assert_eq!(outcome, TickOutcome::BackedUp(EpochId::new(5)));
        assert_eq!(p2p.get_calls.load(Ordering::SeqCst), 1);
        assert_eq!(last_epoch, Some(EpochId::new(5)));
        let stored = storage.load_keyshares().await.unwrap();
        assert_eq!(stored.first().unwrap().key_id.epoch_id, EpochId::new(5));
    }

    #[tokio::test]
    async fn backup_tick__should_skip_when_epoch_already_backed_up() {
        // Given
        let p2p = FakeP2p::new();
        let storage = FakeStorage::empty();
        let contract = FakeContract {
            state: running_state_with_epoch(5),
        };
        let mut last_epoch = Some(EpochId::new(5));

        // When
        let outcome = backup_tick(&p2p, &storage, &contract, &mut last_epoch)
            .await
            .unwrap();

        // Then
        assert_eq!(
            outcome,
            TickOutcome::Skipped(SkipReason::AlreadyCurrent(EpochId::new(5)))
        );
        assert_eq!(p2p.get_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn backup_tick__should_back_up_again_when_epoch_advances() {
        // Given
        let p2p = FakeP2p::new();
        let storage = FakeStorage::empty();
        let contract = FakeContract {
            state: running_state_with_epoch(6),
        };
        let mut last_epoch = Some(EpochId::new(5));

        // When
        let outcome = backup_tick(&p2p, &storage, &contract, &mut last_epoch)
            .await
            .unwrap();

        // Then
        assert_eq!(outcome, TickOutcome::BackedUp(EpochId::new(6)));
        assert_eq!(p2p.get_calls.load(Ordering::SeqCst), 1);
        assert_eq!(last_epoch, Some(EpochId::new(6)));
    }

    #[tokio::test]
    async fn backup_tick__should_skip_when_not_in_backup_state() {
        // Given
        let p2p = FakeP2p::new();
        let storage = FakeStorage::empty();
        let contract = FakeContract {
            state: ProtocolContractState::NotInitialized,
        };
        let mut last_epoch = None;

        // When
        let outcome = backup_tick(&p2p, &storage, &contract, &mut last_epoch)
            .await
            .unwrap();

        // Then
        assert_eq!(outcome, TickOutcome::Skipped(SkipReason::NotBackupState));
        assert_eq!(p2p.get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(last_epoch, None);
    }

    #[tokio::test]
    async fn run_service__should_stop_when_shutdown_requested() {
        // Given
        let p2p = FakeP2p::new();
        let storage = FakeStorage::empty();
        let contract = FakeContract {
            state: running_state_with_epoch(5),
        };
        let shutdown = CancellationToken::new();
        let shutdown_for_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            run_service(
                &p2p,
                &storage,
                &contract,
                Duration::from_millis(20),
                shutdown_for_task,
            )
            .await
        });

        // When
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();

        // Then
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("service should stop after shutdown")
            .expect("service task should not panic");
        result.expect("service should return Ok on shutdown");
    }
}
