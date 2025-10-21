use std::{sync::Arc, time::Duration};

use anyhow::Context;
use backon::{ExponentialBuilder, Retryable};
use ed25519_dalek::VerifyingKey;
use futures::TryFutureExt;
use mpc_contract::primitives::key_state::Keyset;
use near_sdk::AccountId;
use tokio::sync::{watch, RwLock};
use tokio_util::sync::CancellationToken;

use crate::{
    indexer::{
        participants::ContractState,
        tx_sender::TransactionSender,
        types::{ChainSendTransactionRequest, ConcludeNodeMigrationArgs},
    },
    keyshare::{Keyshare, KeyshareStorage},
    migration_service::types::{MigrationInfo, OnboardingJob, OnboardingTask},
};

/// Waits until the node becomes an active participant in the current epoch or
/// terminates if the keyshare channel closes.
/// Internally, this function monitors contract and migration state changes and
/// runs onboarding tasks as needed.
///
/// Returns `Ok(())` when this node is an active participant in the current epoch.
pub(crate) async fn onboard(
    contract_state_receiver: watch::Receiver<ContractState>,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    my_near_account_id: AccountId,
    tls_public_key: VerifyingKey,
    tx_sender: impl TransactionSender,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
) -> anyhow::Result<()> {
    tracing::info!(?my_near_account_id, "starting onboarding");
    let (cancel_monitoring_task, mut onboarding_job_receiver) = start_onboarding_monitoring_task(
        contract_state_receiver,
        my_migration_info_receiver,
        my_near_account_id.clone(),
        tls_public_key,
    );

    loop {
        let OnboardingTask {
            job,
            cancellation_token,
        } = onboarding_job_receiver.borrow_and_update().clone();

        match job {
            OnboardingJob::Done => {
                tracing::info!(?my_near_account_id, "done onboarding");
                cancel_monitoring_task.cancel();
                return Ok(());
            }
            OnboardingJob::WaitForStateChange => {
                tracing::info!(?my_near_account_id, "waiting for state change");
                cancellation_token.cancelled().await;
                continue;
            }
            OnboardingJob::Onboard(importing_keyset) => {
                tracing::info!(?my_near_account_id, "execute onboarding");
                let res = execute_onboarding(
                    importing_keyset.clone(),
                    keyshare_storage.clone(),
                    keyshare_receiver.clone(),
                    tx_sender.clone(),
                    cancellation_token.clone(),
                )
                .await;
                if cancellation_token.is_cancelled() {
                    continue;
                }

                // the only unrecoverable error is if the keyshare sender drops.
                if let Err(err) = res {
                    cancel_monitoring_task.cancel();
                    anyhow::bail!("keyshare sender dropped, quitting onboarding: {}", err);
                }
                // The monitoring function will cancel this task once the contract state changes.
                cancellation_token.cancelled().await;
            }
        }
    }
}

/// Starts a background task that monitors onboarding-related state changes.
///
/// The task watches the contract state and migration info and updates the
/// returned [`watch::Receiver`] with a new [`OnboardingTask`] whenever the
/// corresponding [`OnboardingJob`] changes.
/// The previous task’s cancellation token is triggered each time a new job
/// replaces it.
///
/// Returns a tuple of:
/// - A [`CancellationToken`] to stop the monitoring task.
/// - A [`watch::Receiver<OnboardingTask>`] that emits updates.
fn start_onboarding_monitoring_task(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    mut my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    my_near_account_id: AccountId,
    tls_public_key: VerifyingKey,
) -> (CancellationToken, watch::Receiver<OnboardingTask>) {
    let cancel_monitoring_task = CancellationToken::new();
    let contract = contract_state_receiver.borrow_and_update().clone();
    let my_migration_info = my_migration_info_receiver.borrow_and_update().clone();
    let init_job = OnboardingJob::new(
        my_migration_info,
        contract,
        &my_near_account_id,
        &tls_public_key,
    );
    let cancellation_token = CancellationToken::new();
    let init_task = OnboardingTask {
        job: init_job,
        cancellation_token,
    };

    let cancel_monitoring_task_clone = cancel_monitoring_task.clone();
    let (sender, receiver) = watch::channel(init_task);
    tokio::spawn(async move {
        loop {
            let contract = contract_state_receiver.borrow_and_update().clone();
            let my_migration_info = my_migration_info_receiver.borrow_and_update().clone();
            let job = OnboardingJob::new(
                my_migration_info,
                contract,
                &my_near_account_id,
                &tls_public_key,
            );
            sender.send_if_modified(|watched_state| {
                if watched_state.job != job {
                    watched_state.cancellation_token.cancel();
                    let cancellation_token = CancellationToken::new();
                    *watched_state = OnboardingTask {
                        job,
                        cancellation_token,
                    };
                    true
                } else {
                    false
                }
            });
            tokio::select! {
                _ = contract_state_receiver.changed() => {},
                _ = my_migration_info_receiver.changed() =>  {}
                _ = cancel_monitoring_task_clone.cancelled() => {return;}
            }
        }
    });
    (cancel_monitoring_task, receiver)
}

/// Sends the conclude-onboarding transaction with exponential backoff until successful.
/// No limit on the number of retries, this function will either succeed or get cancelled.
async fn retry_conclude_onboarding(
    importing_keyset: Keyset,
    tx_sender: impl TransactionSender,
) -> anyhow::Result<()> {
    const MIN_DELAY: Duration = Duration::from_secs(2);
    const MAX_TIMEOUT: Duration = Duration::from_secs(60);
    let builder = ExponentialBuilder::new()
        .with_max_delay(MAX_TIMEOUT)
        .with_min_delay(MIN_DELAY)
        .without_max_times();
    let send = move || {
        send_conclude_onboarding(importing_keyset.clone(), tx_sender.clone()).inspect_err(|err| {
            tracing::error!(?err, "error sending conclude migration transaction");
        })
    };
    send.retry(builder).await
}

/// Performs the onboarding process for a given keyset.
///
/// Waits to receive missing keyshares (if not already present) and tries to
/// send the “conclude onboarding” transaction until it succeeds or the provided
/// [`CancellationToken`] is triggered.
///
/// This function returns an error only in case the keyshare_receiver channel is closed.
/// This function returns Ok(()) if it is cancelled or succeeds.
///
/// **Not cancellation-safe!** Needs to be cancelled via `cancel_import_token`
async fn execute_onboarding(
    importing_keyset: Keyset,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    tx_sender: impl TransactionSender,
    cancel_import_token: CancellationToken,
) -> anyhow::Result<()> {
    if keyshare_storage
        .read()
        .await
        .get_keyshares(&importing_keyset)
        .await
        .is_err()
    {
        wait_for_and_import_keyshares(
            &importing_keyset,
            keyshare_storage,
            keyshare_receiver.clone(),
            cancel_import_token.clone(),
        )
        .await?;
    }

    tokio::select! {
        _ = retry_conclude_onboarding(importing_keyset, tx_sender) => {},
        _ = cancel_import_token.cancelled() => {
            tracing::info!("import cancelled");
        },
    }
    Ok(())
}

async fn send_conclude_onboarding(
    imported_keyset: Keyset,
    tx_sender: impl TransactionSender,
) -> anyhow::Result<()> {
    let transaction =
        ChainSendTransactionRequest::ConcludeNodeMigration(ConcludeNodeMigrationArgs {
            keyset: imported_keyset,
        });
    tx_sender.send(transaction).await?;
    Ok(())
}

const START_IMPORT_LOOP_MSG: &str = "starting import loop";
const IMPORT_SUCCESS_MSG: &str = "imported keyshares";
const IMPORT_FAILURE_MSG: &str = "keyshare import failed";
const IMPORT_CANCELLED_MSG: &str = "keyshare import cancelled";
const KEYSHARE_SENDER_CLOSED_MSG: &str = "keyshare sender closed";

/// Waits for keyshares and retries import until successful.
///
/// Returns `Ok(())` if import succeeds or if cancelled.
/// Returns `Err` only if the channel closed.
///
/// This function is **not cancellation-safe** and must be canceled via `cancel_import`.
async fn wait_for_and_import_keyshares(
    contract_keyset: &Keyset,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    mut keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    cancel_import: CancellationToken,
) -> anyhow::Result<()> {
    tracing::info!(START_IMPORT_LOOP_MSG);
    loop {
        let received_keyshares = keyshare_receiver.borrow_and_update().clone();
        if !received_keyshares.is_empty() {
            match keyshare_storage
                .write()
                .await
                .import_backup(received_keyshares, contract_keyset)
                .await
            {
                Ok(_) => {
                    tracing::info!(IMPORT_SUCCESS_MSG);
                    return Ok(());
                }
                Err(err) => {
                    tracing::info!(?err, "{}", IMPORT_FAILURE_MSG);
                }
            }
        }
        tokio::select! {
            changed = keyshare_receiver.changed() => {
                changed.context(KEYSHARE_SENDER_CLOSED_MSG)?;
                continue;
            },
            _ = cancel_import.cancelled() => {
                tracing::info!(IMPORT_CANCELLED_MSG);
                return Ok(());
            },

        };
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        sync::{watch, RwLock},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use crate::{
        config::tests::gen_participant,
        indexer::participants::ContractState,
        keyshare::{generate_key_storage_config, test_utils::KeysetBuilder},
        migration_service::{
            onboarding::{
                wait_for_and_import_keyshares, IMPORT_CANCELLED_MSG, IMPORT_FAILURE_MSG,
                IMPORT_SUCCESS_MSG, KEYSHARE_SENDER_CLOSED_MSG, START_IMPORT_LOOP_MSG,
            },
            types::{
                tests::{
                    make_initializing_contract_case, make_resharing_contract_case,
                    make_running_contract_case, ContractCase, TestNodeId,
                },
                MigrationInfo, OnboardingJob, OnboardingTask,
            },
        },
    };
    use tracing_test::{self, traced_test};

    use super::start_onboarding_monitoring_task;

    const EPOCH_ID: u64 = 3;
    const NUM_KEYS: u64 = 5;
    #[tokio::test]
    #[traced_test]
    async fn test_wait_for_and_import_keyshares_success() {
        let wait_for_log = |msg: String| async move {
            timeout(Duration::from_secs(10), async {
                loop {
                    if logs_contain(&msg) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
            .await
            .expect("Timed out waiting for log message");
        };
        let (config, _temp_dir) = generate_key_storage_config();
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS);
        let cancel_import = CancellationToken::new();
        let (keyshare_sender, keyshare_receiver) = watch::channel(vec![]);
        let contract_keyset = builder.keyset();
        let correct_keyshares = builder.keyshares().to_vec();
        let wrong_builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS);
        let wrong_keyshares = wrong_builder.keyshares().to_vec();

        // sanity check
        assert_ne!(wrong_builder.keyset(), contract_keyset);

        let keyshare_storage = Arc::new(RwLock::new(config.create().await.unwrap()));

        let res = tokio::spawn(async move {
            wait_for_log(START_IMPORT_LOOP_MSG.into()).await;
            keyshare_sender.send(wrong_keyshares).unwrap();
            wait_for_log(IMPORT_FAILURE_MSG.into()).await;
            keyshare_sender.send(correct_keyshares).unwrap();
            wait_for_log(IMPORT_SUCCESS_MSG.into()).await;
        });
        wait_for_and_import_keyshares(
            &contract_keyset,
            keyshare_storage.clone(),
            keyshare_receiver,
            cancel_import,
        )
        .await
        .unwrap();

        res.await.unwrap();
        let found = keyshare_storage
            .read()
            .await
            .get_keyshares(&contract_keyset)
            .await
            .unwrap();
        assert_eq!(found, builder.keyshares().to_vec());
    }

    #[tokio::test]
    #[traced_test]
    async fn test_wait_for_and_import_keyshares_cancel() {
        let (config, _temp_dir) = generate_key_storage_config();
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS);
        let cancel_import = CancellationToken::new();
        let (_keyshare_sender, keyshare_receiver) = watch::channel(vec![]);
        let contract_keyset = builder.keyset();
        cancel_import.cancel();
        let keyshare_storage = Arc::new(RwLock::new(config.create().await.unwrap()));
        wait_for_and_import_keyshares(
            &contract_keyset,
            keyshare_storage,
            keyshare_receiver,
            cancel_import,
        )
        .await
        .unwrap();

        assert!(logs_contain(START_IMPORT_LOOP_MSG));
        assert!(logs_contain(IMPORT_CANCELLED_MSG))
    }

    #[tokio::test]
    async fn test_wait_for_and_import_keyshares_drop_sender() {
        let (config, _temp_dir) = generate_key_storage_config();
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS);
        let cancel_import = CancellationToken::new();
        let keyshare_receiver = {
            let (_keyshare_sender, keyshare_receiver) = watch::channel(vec![]);
            keyshare_receiver
        };
        let contract_keyset = builder.keyset();
        let keyshare_storage = Arc::new(RwLock::new(config.create().await.unwrap()));
        let res = wait_for_and_import_keyshares(
            &contract_keyset,
            keyshare_storage,
            keyshare_receiver,
            cancel_import,
        )
        .await;
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(err.contains(KEYSHARE_SENDER_CLOSED_MSG));
    }

    const INACTIVE_MIGRATION: MigrationInfo = MigrationInfo {
        backup_service_info: None,
        active_migration: false,
    };
    const ACTIVE_MIGRATION: MigrationInfo = MigrationInfo {
        backup_service_info: None,
        active_migration: true,
    };

    async fn conclude_onboarding_and_assert_done(
        contract_case: ContractCase,
        contract_state_sender: &watch::Sender<ContractState>,
        task_receiver: &mut watch::Receiver<OnboardingTask>,
        monitoring_cancellation_token: CancellationToken,
    ) {
        let task = task_receiver.borrow_and_update().clone();
        assert!(!task.cancellation_token.is_cancelled());
        let ContractCase {
            mut contract,
            onboarding_node,
            ..
        } = contract_case;
        contract.change_participant_pk(&onboarding_node.account_id, onboarding_node.p2p_public_key);
        contract_state_sender.send(contract.clone()).unwrap();
        // wait for cancellation
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            task.cancellation_token.cancelled(),
        )
        .await
        .unwrap();
        // now we should be done
        assert!(task.cancellation_token.is_cancelled());
        let task = task_receiver.borrow_and_update().clone();
        assert_eq!(task.job, OnboardingJob::Done);

        monitoring_cancellation_token.cancel();
        assert!(task_receiver.changed().await.is_err());
        assert!(contract_state_sender.is_closed());
    }
    struct OnboardingMonitoringTaskSetup {
        my_migration_info_sender: watch::Sender<MigrationInfo>,
        contract_state_sender: watch::Sender<ContractState>,
        task_receiver: watch::Receiver<OnboardingTask>,
        monitoring_cancellation_token: CancellationToken,
    }
    fn setup_test(onboarding_node: TestNodeId) -> OnboardingMonitoringTaskSetup {
        let (contract_state_sender, contract_state_receiver) =
            watch::channel(ContractState::Invalid);
        let (my_migration_info_sender, my_migration_info_receiver) =
            watch::channel(INACTIVE_MIGRATION);
        let (monitoring_cancellation_token, task_receiver) = start_onboarding_monitoring_task(
            contract_state_receiver,
            my_migration_info_receiver,
            onboarding_node.account_id,
            onboarding_node.p2p_public_key,
        );
        OnboardingMonitoringTaskSetup {
            task_receiver,
            contract_state_sender,
            my_migration_info_sender,
            monitoring_cancellation_token,
        }
    }
    async fn setup_and_assert_invalid_state(
        onboarding_node: TestNodeId,
    ) -> OnboardingMonitoringTaskSetup {
        let mut setup = setup_test(onboarding_node);
        let OnboardingMonitoringTaskSetup {
            task_receiver,
            my_migration_info_sender,
            ..
        } = &mut setup;
        let task = task_receiver.borrow_and_update().clone();
        assert_eq!(task.job, OnboardingJob::WaitForStateChange);
        assert!(!task.cancellation_token.is_cancelled());
        // active migration does not matter if the contract is not in running state.
        my_migration_info_sender.send(ACTIVE_MIGRATION).unwrap();
        assert!(!task.cancellation_token.is_cancelled());
        setup
    }
    #[tokio::test]
    async fn test_start_onboarding_monitoring_task_running() {
        let non_participant = gen_participant();
        let onboarding_node_p2p_public_key = non_participant.p2p_public_key;
        let (running_state_case, keyset) =
            make_running_contract_case(onboarding_node_p2p_public_key);
        let OnboardingMonitoringTaskSetup {
            mut task_receiver,
            contract_state_sender,
            monitoring_cancellation_token,
            ..
        } = setup_and_assert_invalid_state(running_state_case.onboarding_node.clone()).await;

        let task = task_receiver.borrow_and_update().clone();
        contract_state_sender
            .send(running_state_case.contract.clone())
            .unwrap();
        // wait for cancellation, we should be onboarding
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            task.cancellation_token.cancelled(),
        )
        .await
        .unwrap();
        assert!(task.cancellation_token.is_cancelled());
        let task = task_receiver.borrow_and_update().clone();
        assert_eq!(task.job, OnboardingJob::Onboard(keyset));

        conclude_onboarding_and_assert_done(
            running_state_case,
            &contract_state_sender,
            &mut task_receiver,
            monitoring_cancellation_token,
        )
        .await;
    }
    #[tokio::test]
    async fn test_start_onboarding_monitoring_task_resharing() {
        let non_participant = gen_participant();
        let onboarding_node_p2p_public_key = non_participant.p2p_public_key;
        let resharing_state_case = make_resharing_contract_case(onboarding_node_p2p_public_key);
        let OnboardingMonitoringTaskSetup {
            mut task_receiver,
            contract_state_sender,
            monitoring_cancellation_token,
            ..
        } = setup_and_assert_invalid_state(resharing_state_case.onboarding_node.clone()).await;
        conclude_onboarding_and_assert_done(
            resharing_state_case,
            &contract_state_sender,
            &mut task_receiver,
            monitoring_cancellation_token,
        )
        .await;
    }
    #[tokio::test]
    async fn test_start_onboarding_monitoring_task_initializing() {
        let non_participant = gen_participant();
        let onboarding_node_p2p_public_key = non_participant.p2p_public_key;
        let initializing_contract_case =
            make_initializing_contract_case(onboarding_node_p2p_public_key);
        let OnboardingMonitoringTaskSetup {
            mut task_receiver,
            contract_state_sender,
            monitoring_cancellation_token,
            ..
        } = setup_and_assert_invalid_state(initializing_contract_case.onboarding_node.clone())
            .await;
        conclude_onboarding_and_assert_done(
            initializing_contract_case,
            &contract_state_sender,
            &mut task_receiver,
            monitoring_cancellation_token,
        )
        .await;
    }
}
