use std::{sync::Arc, time::Duration};

use anyhow::Context;
use backon::{ExponentialBuilder, Retryable};
use futures::TryFutureExt;
use near_mpc_crypto_types::Keyset;
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    indexer::{
        tx_sender::TransactionSender,
        types::{ChainSendTransactionRequest, ConcludeNodeMigrationArgs},
    },
    keyshare::{Keyshare, KeyshareStorage},
    migration_service::{
        types::{MigrationInfo, NodeJob},
        wait_until_job_changes,
    },
};

/// Runs onboarding for the given keyset until either:
///   - `execute_onboarding` returns (success: conclude-tx submitted and contract
///     reflected completion, or unrecoverable error: keyshare sender dropped), or
///   - the unified `job_receiver` moves to a different variant (the role changed,
///     e.g. to `NodeJob::Initialize` once we became an active participant, or
///     to `NodeJob::WaitForStateChange` if the contract changed underneath us).
///
/// In the role-change case, we fire the import cancellation token to stop the
/// in-flight import cleanly. The outer coordinator loop reads the next
/// `NodeJob` from the same receiver and dispatches the new arm.
pub(crate) async fn run_onboarding(
    importing_keyset: Keyset,
    mut job_receiver: watch::Receiver<NodeJob>,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    tx_sender: impl TransactionSender,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
) -> anyhow::Result<()> {
    let cancel_import_token = CancellationToken::new();
    tokio::select! {
        // execute_onboarding returns Err only if the keyshare sender drops
        // (unrecoverable). Returns Ok when the conclude tx is reflected on
        // chain — at that point the role moves to Active and the coordinator
        // loop's next iteration will pick up NodeJob::Initialize / Run.
        res = execute_onboarding(
            importing_keyset,
            keyshare_storage,
            keyshare_receiver,
            tx_sender,
            my_migration_info_receiver,
            cancel_import_token.clone(),
        ) => {
            res.context("execute_onboarding failed (keyshare sender dropped)")
        }
        res = wait_until_job_changes(
            &mut job_receiver,
            |j| matches!(j, NodeJob::Onboard(_)),
        ) => {
            tracing::info!("onboarding: role changed; cancelling import");
            cancel_import_token.cancel();
            res
        }
    }
}

/// Retries `conclude_node_migration` until the contract reflects completion.
///
/// `tx_sender::send` returns `Ok` once the tx is applied — even if the
/// contract method returned `Err` and rolled back. So we also wait for
/// `active_migration` to flip false on the local `MigrationInfo` watch
/// (cleared when the contract removes our migration record on success); if
/// it doesn't, we retry.
async fn retry_conclude_onboarding(
    importing_keyset: Keyset,
    tx_sender: impl TransactionSender,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
) -> anyhow::Result<()> {
    const MIN_DELAY: Duration = Duration::from_secs(2);
    const MAX_TIMEOUT: Duration = Duration::from_secs(60);
    const POST_TX_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);

    let builder = ExponentialBuilder::new()
        .with_max_delay(MAX_TIMEOUT)
        .with_min_delay(MIN_DELAY)
        .without_max_times();

    let attempt = move || {
        let importing_keyset = importing_keyset.clone();
        let tx_sender = tx_sender.clone();
        let mut my_migration_info_receiver = my_migration_info_receiver.clone();
        async move {
            send_conclude_onboarding(importing_keyset, tx_sender)
                .inspect_err(|err| {
                    tracing::error!(?err, "error sending conclude migration transaction");
                })
                .await?;
            wait_for_active_migration_to_clear(
                &mut my_migration_info_receiver,
                POST_TX_OBSERVATION_TIMEOUT,
            )
            .await
            .inspect_err(|err| {
                tracing::warn!(
                    ?err,
                    "conclude migration tx submitted but contract has not reflected completion; retrying"
                );
            })
        }
    };
    attempt.retry(builder).await
}

/// Waits up to `timeout` for `active_migration` to flip false.
async fn wait_for_active_migration_to_clear(
    receiver: &mut watch::Receiver<MigrationInfo>,
    timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, async {
        loop {
            if !receiver.borrow_and_update().active_migration {
                return Ok::<(), anyhow::Error>(());
            }
            receiver
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("migration info channel closed"))?;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("active_migration did not clear within {timeout:?}"))?
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
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
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
        _ = retry_conclude_onboarding(
            importing_keyset,
            tx_sender,
            my_migration_info_receiver,
        ) => {},
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

    use rand::SeedableRng as _;
    use tokio::{
        sync::{RwLock, watch},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use crate::{
        keyshare::{generate_key_storage_config, test_utils::KeysetBuilder},
        migration_service::onboarding::{
            IMPORT_CANCELLED_MSG, IMPORT_FAILURE_MSG, IMPORT_SUCCESS_MSG,
            KEYSHARE_SENDER_CLOSED_MSG, START_IMPORT_LOOP_MSG, wait_for_and_import_keyshares,
        },
    };
    use tracing_test::{self, traced_test};

    const EPOCH_ID: u64 = 3;
    const NUM_KEYS: u64 = 5;
    #[tokio::test]
    #[traced_test]
    async fn test_wait_for_and_import_keyshares_success() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
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
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS, &mut rng);
        let cancel_import = CancellationToken::new();
        let (keyshare_sender, keyshare_receiver) = watch::channel(vec![]);
        let contract_keyset = builder.keyset();
        let correct_keyshares = builder.keyshares().to_vec();
        let wrong_builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS, &mut rng);
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
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let (config, _temp_dir) = generate_key_storage_config();
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS, &mut rng);
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
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let (config, _temp_dir) = generate_key_storage_config();
        let builder = KeysetBuilder::new_populated(EPOCH_ID, NUM_KEYS, &mut rng);
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
        let err = res
            .expect_err("Dropping the sender should stop keyshare import")
            .to_string();
        assert!(err.contains(KEYSHARE_SENDER_CLOSED_MSG));
    }

}
