use derive_more::From;
use itertools::Itertools;
use mpc_contract::tee::proposal::MpcDockerImageHash;
use std::{future::Future, io, panic, path::PathBuf};
use thiserror::Error;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    select,
    sync::{
        mpsc::{self, error::TrySendError},
        watch,
    },
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use mockall::automock;
#[cfg_attr(test, automock)]
pub trait AllowedImageHashesStorage {
    fn set(
        &mut self,
        approved_hashes: &[MpcDockerImageHash],
    ) -> impl Future<Output = Result<(), io::Error>> + Send;
}

#[derive(From)]
pub struct AllowedImageHashesFile {
    file_path: PathBuf,
}

// important: must stay aligned with the launcher implementation in:
// mpc/tee_launcher/launcher.py
const JSON_KEY_APPROVED_HASHES: &str = "approved_hashes";

impl AllowedImageHashesStorage for AllowedImageHashesFile {
    async fn set(&mut self, approved_hashes: &[MpcDockerImageHash]) -> Result<(), io::Error> {
        tracing::info!(
            ?self.file_path,
            len = approved_hashes.len(),
            "Writing approved MPC image hashes to disk (JSON format)."
        );

        let hash_strings: Vec<String> = approved_hashes
            .iter()
            .map(|h| format!("sha256:{}", h.as_hex()))
            .collect();

        let json = serde_json::json!({
            JSON_KEY_APPROVED_HASHES: hash_strings
        });

        tracing::debug!(
            %JSON_KEY_APPROVED_HASHES,
            approved = ?hash_strings,
            json = %json.to_string(),
            "approved image hashes JSON that will be written to disk"
        );

        let tmp_path = self.file_path.with_extension("tmp");
        // Write to a temporary file first.
        // This prevents corruption of the final file if the node crashes or power is lost mid-write.
        // Only once the temp file is fully written do we atomically rename() it into place.
        {
            let mut file = OpenOptions::new()
                .truncate(true)
                .create(true)
                .write(true)
                .open(&tmp_path)
                .await?;

            file.write_all(json.to_string().as_bytes()).await?;
            file.flush().await?;
        }
        // Atomic replace: POSIX rename() ensures that either the old file or the new file exists.
        // The final file is never left in a partially-written state.
        tokio::fs::rename(&tmp_path, &self.file_path).await?;

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ExitError {
    #[error("Could not write allowed image hash to storage provider.")]
    StorageProviderError(#[from] io::Error),
    #[error(
        "The provided watcher that tracks the allowed image hashes on the contract was closed."
    )]
    IndexerClosed,
}

/// Creates a future that monitors the latest allowed image hashes in
/// `allowed_hashes_in_contract` and writes them to the provided storage implementation `image_hash_storage`.
///
/// The future will exit with an error and send a shutdown signal on the `shutdown_signal_sender` if:
/// - The provided [AllowedImageHashesStorage::set] implementation returns an [io::Error]
/// - The provided `allowed_hashes_in_contract` channel is closed.
///
/// ### Cancellation Safety:
/// This future is only cancel safe iff the provided storage implementation is cancel safe. To cancel this future
/// gracefully please cancel the parent of the cancellation token that is passed as an argument, `cancellation_token`.
pub async fn monitor_allowed_image_hashes<Storage>(
    cancellation_token: CancellationToken,
    current_image: MpcDockerImageHash,
    allowed_hashes_in_contract: watch::Receiver<Vec<MpcDockerImageHash>>,
    image_hash_storage: Storage,
    shutdown_signal_sender: mpsc::Sender<()>,
) -> Result<(), ExitError>
where
    Storage: AllowedImageHashesStorage + Send + Sync + 'static,
{
    let manager: AllowedImageHashesWatcher<Storage> = AllowedImageHashesWatcher {
        image_hash_storage,
        cancellation_token,
        allowed_hashes_in_contract,
        current_image,
        shutdown_signal_sender,
    };

    manager.run_event_loop().await
}

struct AllowedImageHashesWatcher<A> {
    cancellation_token: CancellationToken,
    allowed_hashes_in_contract: watch::Receiver<Vec<MpcDockerImageHash>>,
    current_image: MpcDockerImageHash,
    image_hash_storage: A,
    shutdown_signal_sender: mpsc::Sender<()>,
}

/// Send shutdown signal when watcher exits if
/// it was not due to cancellation token being cancelled.
impl<Storage> Drop for AllowedImageHashesWatcher<Storage> {
    fn drop(&mut self) {
        let exiting_without_cancelled_token = !self.cancellation_token.is_cancelled();

        if exiting_without_cancelled_token {
            let sent_shutdown_signal = self.shutdown_signal_sender.try_send(());
            if let Err(TrySendError::Closed(_)) = sent_shutdown_signal {
                tracing::error!("Shutdown signal receiver closed.");
            }
        }
    }
}

impl<Storage> AllowedImageHashesWatcher<Storage>
where
    Storage: AllowedImageHashesStorage + Send + Sync + 'static,
{
    async fn run_event_loop(mut self) -> Result<(), ExitError> {
        // First value is marked as seen by default in `watch::Receiver` implementation
        // Mark it changed to make sure we process the initial value in the select arm below.
        self.allowed_hashes_in_contract.mark_changed();

        loop {
            select! {
                _ = self.cancellation_token.cancelled() => {
                    break Ok(());
                }

                watcher_result = self.allowed_hashes_in_contract.changed() => {
                    if watcher_result.is_err() {
                        break Err(ExitError::IndexerClosed);
                    }

                    self.handle_allowed_image_hashes_update().await?;
                }
            }
        }
    }

    /// Handles an updated list of allowed image hashes in the `allowed_hashes_in_contract` watcher.
    /// An ordered list of allowed image hashes is written to the `image_hash_storage`, from
    /// most to least recent image hash.
    /// Returns an [io::Error] if the [AllowedImageHashesStorage::set] implementation fails.
    async fn handle_allowed_image_hashes_update(&mut self) -> Result<(), io::Error> {
        tracing::info!(
            "Set of allowed image hashes on contract has changed. Storing hashes to disk."
        );

        let allowed_hashes = self.allowed_hashes_in_contract.borrow_and_update().clone();

        if allowed_hashes.is_empty() {
            tracing::warn!("Indexer provided an empty list of allowed image hashes.");
            return Ok(());
        }

        // Write all hashes, newest-first (as provided by contract)
        self.image_hash_storage.set(&allowed_hashes).await?;

        let running_image_is_not_allowed = !allowed_hashes.iter().contains(&self.current_image);

        if running_image_is_not_allowed {
            tracing::error!("Currently running node image is NOT in the allowed hash list!");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mockall::predicate;
    use rstest::rstest;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::{mpsc::error::TryRecvError, Notify};
    use tokio_util::time::FutureExt;

    const TEST_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

    fn image_hash_1() -> MpcDockerImageHash {
        MpcDockerImageHash::from([1; 32])
    }

    fn image_hash_2() -> MpcDockerImageHash {
        MpcDockerImageHash::from([2; 32])
    }

    fn image_hash_3() -> MpcDockerImageHash {
        MpcDockerImageHash::from([3; 32])
    }

    /// Ensures that whenever the allowed image hash list changes,
    /// the MPC node writes the full list of allowed hashes to storage,
    /// preserving the ordering received from the contract.
    ///
    /// The contract always sends hashes oldest → newest, and the watcher
    /// must pass the entire vector untouched to the storage backend.
    #[rstest]
    #[tokio::test]
    async fn test_allowed_image_hash_list_is_written() {
        let allowed_images = vec![image_hash_1(), image_hash_2(), image_hash_3()];
        for current_hash in &allowed_images[..2] {
            let cancellation_token = CancellationToken::new();
            let (sender, receiver) = watch::channel(allowed_images.clone());
            let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

            let write_is_called = Arc::new(Notify::new());

            let mut storage_mock = MockAllowedImageHashesStorage::new();
            {
                let write_is_called = write_is_called.clone();
                storage_mock
                    .expect_set()
                    .once()
                    .with(predicate::eq(allowed_images.clone()))
                    .returning(move |_| {
                        write_is_called.notify_one();
                        Box::pin(async { Ok(()) })
                    });
            }

            let _join_handle = tokio::spawn(monitor_allowed_image_hashes(
                cancellation_token.child_token(),
                current_hash.clone(),
                receiver,
                storage_mock,
                sender_shutdown,
            ));

            write_is_called.notified().await;

            assert_matches!(
                receiver_shutdown.try_recv(),
                Err(TryRecvError::Empty),
                "Shutdown signal was sent unexpectedly."
            );

            assert!(!sender.is_closed(), "Event loop should be running.");
        }
    }

    /// Verifies that if writing the allowed image hashes to the storage
    /// backend fails (e.g., disk I/O error), the MPC node:
    ///
    /// - propagates the error as `ExitError::StorageProviderError`
    /// - sends a shutdown signal to the node supervisor
    /// - stops the watcher loop cleanly
    #[rstest]
    #[case::image_is_allowed(image_hash_1(), vec![image_hash_1()])]
    #[case::image_is_disallowed(image_hash_2(), vec![image_hash_1()])]
    #[tokio::test]
    async fn test_shutdown_signal_is_sent_on_write_error(
        #[case] current_image: MpcDockerImageHash,
        #[case] allowed_images: Vec<MpcDockerImageHash>,
    ) {
        let mut mock = MockAllowedImageHashesStorage::new();

        mock.expect_set()
            .once()
            .returning(|_| Box::pin(async { Err(io::Error::other("Expected test error.")) }));

        let cancellation_token = CancellationToken::new();
        let (_sender, receiver) = watch::channel(allowed_images);
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            current_image,
            receiver,
            mock,
            sender_shutdown,
        ));

        receiver_shutdown
            .recv()
            .await
            .expect("Shutdown signal is sent.");

        let result = join_handle.await.unwrap();
        assert_matches!(result, Err(ExitError::StorageProviderError(_)));
    }

    /// Ensures that when the allowed image hash list changes and the
    /// current running MPC node image is *not* included in the updated
    /// allowed list, the MPC node still:
    ///
    /// - writes the full allowed list to storage
    /// - does *not* send a shutdown signal immediately
    /// - keeps the event loop alive
    #[tokio::test]
    async fn test_current_image_not_allowed() {
        let current_image = image_hash_1();
        let allowed_image = image_hash_2();

        let allowed_list = vec![allowed_image.clone()];

        let cancellation_token = CancellationToken::new();
        let (_sender, receiver) = watch::channel(allowed_list.clone());
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let write_is_called = Arc::new(Notify::new());

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            let write_is_called = write_is_called.clone();
            storage_mock
                .expect_set()
                .once()
                .with(predicate::eq(allowed_list.clone()))
                .returning(move |_| {
                    write_is_called.notify_one();
                    Box::pin(async { Ok(()) })
                });
        }

        let _join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            current_image,
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        write_is_called.notified().await;

        assert_matches!(
            receiver_shutdown.try_recv(),
            Err(TryRecvError::Empty),
            "Shutdown signal was sent unexpectedly."
        );

        let event_loop_is_alive = !receiver_shutdown.is_closed();
        assert!(event_loop_is_alive, "Event loop should be running.");
    }

    /// Validates behavior when the `watch::Receiver` for allowed image
    /// hashes is closed unexpectedly (e.g., indexer process died).
    ///
    /// Expected behavior:
    /// - the watcher detects the closure and exits with `ExitError::IndexerClosed`
    /// - the watcher still writes the final received allowed hash list
    ///   to storage before exiting
    /// - a shutdown signal is sent to the node supervisor
    #[tokio::test]
    async fn test_allowed_hashes_watcher_is_closed() {
        let cancellation_token = CancellationToken::new();

        // Contract sends 3 allowed hashes
        let allowed_images = vec![image_hash_1(), image_hash_2(), image_hash_3()];

        // Create the watcher channel and then immediately drop sender
        let (sender, receiver) = watch::channel(allowed_images.clone());
        drop(sender); // <- simulate indexer shutting down

        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            let expected = allowed_images.clone();

            storage_mock
                .expect_set()
                .once()
                .with(predicate::eq(expected))
                .returning(|_| Box::pin(async { Ok(()) }));
        }

        let join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            image_hash_1(), // current image (irrelevant for this test)
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        let exit_reason = join_handle
            .timeout(TEST_TIMEOUT_DURATION)
            .await
            .expect("Event loop should exit within timeout")
            .unwrap();

        assert_matches!(exit_reason, Err(ExitError::IndexerClosed));

        assert_matches!(
            receiver_shutdown.try_recv(),
            Ok(()),
            "Shutdown signal should be sent when running image is disallowed."
        );
    }

    /// Ensures the watcher writes the full list of allowed image hashes to storage
    /// when the contract provides multiple hashes, preserving order and making only
    /// a single storage `set()` call.
    #[tokio::test]
    async fn test_full_hash_list_is_written_to_storage() {
        // Contract sends a list of three hashes
        let allowed_images = vec![image_hash_1(), image_hash_2(), image_hash_3()];
        let full_list = allowed_images.clone();

        // Current running image (could be any)
        let current_image = image_hash_1();

        let cancellation_token = CancellationToken::new();
        let (_sender, receiver) = watch::channel(allowed_images.clone());
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let write_is_called = Arc::new(Notify::new());

        // Mock storage expecting exactly the full list
        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            let expected = full_list.clone();
            let write_is_called = write_is_called.clone();

            storage_mock
                .expect_set()
                .once()
                .with(predicate::eq(expected))
                .returning(move |_| {
                    write_is_called.notify_one();
                    Box::pin(async { Ok(()) })
                });
        }

        let _join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            current_image,
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        // Wait for the write
        write_is_called.notified().await;

        // No shutdown expected
        assert_matches!(
            receiver_shutdown.try_recv(),
            Err(TryRecvError::Empty),
            "Shutdown signal should not be sent"
        );
    }

    /// Verifies that an empty allowed-hash list from the contract is handled safely:
    /// the watcher must not write to storage, must not send a shutdown signal,
    /// and must continue running without panicking.
    #[tokio::test]
    async fn test_empty_hash_list_does_not_panic() {
        // Contract sends an empty list
        let allowed_images: Vec<MpcDockerImageHash> = vec![];
        let current_image = image_hash_1();

        let cancellation_token = CancellationToken::new();
        let (_sender, receiver) = watch::channel(allowed_images);
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        // Storage must NOT be called
        let mut storage_mock = MockAllowedImageHashesStorage::new();
        storage_mock.expect_set().never();

        // Spawn watcher
        let _join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token.child_token(),
            current_image,
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        // No shutdown signal should be sent
        assert_matches!(
            receiver_shutdown.try_recv(),
            Err(TryRecvError::Empty),
            "Shutdown should NOT be sent when list is empty"
        );
    }

    #[test]
    fn test_json_key_matches_launcher() {
        // important: must stay aligned with the launcher implementation in:
        // mpc/tee_launcher/launcher.py
        assert_eq!(JSON_KEY_APPROVED_HASHES, "approved_hashes");
    }
}
