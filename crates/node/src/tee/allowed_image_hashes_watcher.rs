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
        latest_allowed_image_hash: &MpcDockerImageHash,
    ) -> impl Future<Output = Result<(), io::Error>> + Send;
}

#[derive(From)]
pub struct AllowedImageHashesFile {
    file_path: PathBuf,
}

impl AllowedImageHashesStorage for AllowedImageHashesFile {
    async fn set(
        &mut self,
        latest_allowed_image_hash: &MpcDockerImageHash,
    ) -> Result<(), io::Error> {
        tracing::info!(
            ?self.file_path,
            ?latest_allowed_image_hash,
            "Creating file handle to store latest allowed image hash."
        );

        let mut file_handle = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(&self.file_path)
            .await?;

        tracing::info!(
            ?self.file_path,
            ?latest_allowed_image_hash,
            "Writing latest allowed image hash to disk."
        );

        // Add the sha256: prefix before writing to disk (this is the format expected by launcher)
        let image_hash = format!("sha256:{}", latest_allowed_image_hash.as_hex());
        file_handle.write_all(image_hash.as_bytes()).await?;
        file_handle.flush().await?;

        tracing::info!(
            ?self.file_path,
            ?latest_allowed_image_hash,
            "Successfully written latest allowed image hash to disk."
        );

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
    /// The latest allowed image hash is written to the `image_hash_storage`.
    ///
    /// Returns an [io::Error] if the [AllowedImageHashesStorage::set] implementation fails.
    async fn handle_allowed_image_hashes_update(&mut self) -> Result<(), io::Error> {
        tracing::info!(
            "Set of allowed image hashes on contract has changed. Storing hashes to disk."
        );
        let allowed_image_hashes = self.allowed_hashes_in_contract.borrow_and_update().clone();

        let image_hash_storage = &mut self.image_hash_storage;
        let Some(latest_allowed_image_hash) = allowed_image_hashes.last() else {
            tracing::warn!("Indexer provided an empty set of allowed TEE image hashes.");
            return Ok(());
        };

        image_hash_storage.set(latest_allowed_image_hash).await?;

        let running_image_is_not_allowed =
            !allowed_image_hashes.iter().contains(&self.current_image);

        if running_image_is_not_allowed {
            tracing::error!("Currently running node image not in set of allowed image hashes.");
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
    use std::{io::ErrorKind, sync::Arc, time::Duration};
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

    /// Assert that the image with highest block height is always written to storage.
    #[rstest]
    #[tokio::test]
    async fn test_latest_allowed_image_hash_is_written() {
        let allowed_images = vec![image_hash_1(), image_hash_2(), image_hash_3()];
        let most_recent_hash = allowed_images.last().unwrap().clone();
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
                    // Verify that the most recently allowed image hash is written
                    .with(predicate::eq(most_recent_hash.clone()))
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
            let event_loop_is_alive = !sender.is_closed();
            assert!(event_loop_is_alive, "Event loop should be running.");
        }
    }

    #[rstest]
    #[case::image_is_allowed(image_hash_1(), vec![image_hash_1()])]
    /// - `ErrorKind::StorageProviderError` is returned also if current image is disallowed.
    #[case::image_is_disallowed(image_hash_2(), vec![image_hash_1()])]
    #[tokio::test]
    async fn test_shutdown_signal_is_sent_on_write_error(
        #[case] current_image: MpcDockerImageHash,
        #[case] allowed_images: Vec<MpcDockerImageHash>,
    ) {
        let mut mock = MockAllowedImageHashesStorage::new();

        mock.expect_set().once().returning(|_| {
            Box::pin(async { Err(io::Error::new(ErrorKind::Other, "Expected test error.")) })
        });

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

        let event_loop_exit_result = join_handle.await.unwrap();
        assert_matches!(
            event_loop_exit_result,
            Err(ExitError::StorageProviderError(_))
        );
    }

    #[tokio::test]
    async fn test_current_image_not_allowed() {
        let current_image = image_hash_1();
        let allowed_image = image_hash_2();

        let cancellation_token = CancellationToken::new();
        let (_sender, receiver) = watch::channel(vec![allowed_image.clone()]);
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let write_is_called = Arc::new(Notify::new());

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            let write_is_called = write_is_called.clone();
            storage_mock
                .expect_set()
                .once()
                // Verify that the latest allowed image is written
                .with(predicate::eq(allowed_image))
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

    #[tokio::test]
    async fn test_allowed_hashes_watcher_is_closed() {
        let cancellation_token = CancellationToken::new();
        let (sender, receiver) = watch::channel(vec![image_hash_1()]);
        drop(sender);

        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            storage_mock
                .expect_set()
                .once()
                // Verify that the latest allowed image is written
                .with(predicate::eq(image_hash_1()))
                .returning(move |_| Box::pin(async { Ok(()) }));
        }

        let join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            image_hash_1(),
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        let exit_reason = join_handle
            .timeout(TEST_TIMEOUT_DURATION)
            .await
            .expect("Event loop responds exits within timeout.")
            .unwrap();

        assert_matches!(exit_reason, Err(ExitError::IndexerClosed));

        assert_matches!(
            receiver_shutdown.try_recv(),
            Ok(()),
            "Shutdown signal should be sent when running image is disallowed."
        );
    }
}
