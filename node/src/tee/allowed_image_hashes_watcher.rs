use itertools::Itertools;
use mpc_contract::tee::proposal::{AllowedDockerImageHash, DockerImageHash};
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
use tracing::{error, info, warn};

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait AllowedImageHashesStorage {
    fn set(
        &mut self,
        latest_allowed_image_hash: &AllowedDockerImageHash,
    ) -> impl Future<Output = Result<(), io::Error>> + Send;
}

pub struct AllowedImageHashesFile {
    file_path: PathBuf,
}

impl AllowedImageHashesFile {
    pub async fn new(file_path: PathBuf) -> Result<Self, io::Error> {
        // Make sure the provided path exists.
        let _file_handle = OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&file_path)
            .await?;

        Ok(Self { file_path })
    }
}

impl AllowedImageHashesStorage for AllowedImageHashesFile {
    async fn set(
        &mut self,
        latest_allowed_image_hash: &AllowedDockerImageHash,
    ) -> Result<(), io::Error> {
        let mut file_handle = OpenOptions::new()
            .truncate(true)
            .write(true)
            .open(&self.file_path)
            .await?;

        let image_hash = latest_allowed_image_hash.image_hash.as_hex();
        file_handle.write_all(image_hash.as_bytes()).await?;
        file_handle.flush().await?;

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ExitError {
    #[error("The local image that is running is not in the set of allowed image hashes on the contract.")]
    RunningImageIsDisallowed,
    #[error("Could not write to the provided storage provider.")]
    StorageProviderError(#[from] io::Error),
    #[error(
        "The provided watcher that tracks the allowed image hashes on the contract was closed."
    )]
    IndexerClosed,
}

/// Creates a future that monitors the latest allowed image hashes in
/// `allowed_hashes_in_contract` and writes them to the provided storage `image_hash_storage`.
///
/// If the node's current running image is not in the latest allowed images on the contract
/// a shutdown signal will be sent on the provided `shutdown_signal_sender`.
///
/// ### Cancellation Safety:
/// This future is only cancel safe iff the provided storage implementation is cancel safe. To cancel this future
/// gracefully please cancel the parent of the cancellation token that is passed as an argument, `cancellation_token`.
pub async fn monitor_allowed_image_hashes<Storage>(
    cancellation_token: CancellationToken,
    current_image: DockerImageHash,
    allowed_hashes_in_contract: watch::Receiver<Vec<AllowedDockerImageHash>>,
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
    allowed_hashes_in_contract: watch::Receiver<Vec<AllowedDockerImageHash>>,
    current_image: DockerImageHash,
    image_hash_storage: A,
    shutdown_signal_sender: mpsc::Sender<()>,
}

impl<Storage> AllowedImageHashesWatcher<Storage>
where
    Storage: AllowedImageHashesStorage + Send + Sync + 'static,
{
    async fn run_event_loop(mut self) -> Result<(), ExitError> {
        // First value is marked as seen by default in `watch::Receiver` implementation
        // Mark it changed to make sure we process the initial value in the select arm below.
        self.allowed_hashes_in_contract.mark_changed();

        let exit_reason = loop {
            select! {
                _ = self.cancellation_token.cancelled() => {
                    return Ok(());
                }

                watcher_result = self.allowed_hashes_in_contract.changed() => {
                    if watcher_result.is_err() {
                        break ExitError::IndexerClosed;
                    }

                    info!("Set of allowed image hashes on contract has changed. Storing hashes to disk.");
                    let allowed_image_hashes = self.allowed_hashes_in_contract.borrow_and_update().clone();

                    let image_hash_storage = &mut self.image_hash_storage;
                    let Some(latest_allowed_image_hash) = allowed_image_hashes.iter().max_by_key(|image| image.added) else {
                        warn!("Indexer provided an empty set of allowed TEE image hashes.");
                        continue;
                    };

                    if let Err(err) = image_hash_storage.set(latest_allowed_image_hash).await.map_err(ExitError::StorageProviderError) {
                        break err;
                    };

                    let local_image_is_allowed = allowed_image_hashes
                        .iter()
                        .map(|image| &image.image_hash)
                        .contains(&self.current_image);

                    if !local_image_is_allowed {
                        warn!("Current node image not in set of allowed image hashes. Sending shut down signal.");
                        break ExitError::RunningImageIsDisallowed;
                    }
                }
            }
        };

        let sent_shutdown_signal = self.shutdown_signal_sender.try_send(());
        if let Err(TrySendError::Closed(_)) = sent_shutdown_signal {
            error!("Shutdown signal receiver closed.");
        }

        Err(exit_reason)
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

    const IMAGE_HASH_1: AllowedDockerImageHash = AllowedDockerImageHash {
        image_hash: DockerImageHash([1; 32]),
        added: 1,
    };
    const IMAGE_HASH_2: AllowedDockerImageHash = AllowedDockerImageHash {
        image_hash: DockerImageHash([2; 32]),
        added: 2,
    };
    const IMAGE_HASH_3: AllowedDockerImageHash = AllowedDockerImageHash {
        image_hash: DockerImageHash([3; 32]),
        added: 3,
    };

    /// Assert that the image with highest block height is always written to storage.
    #[rstest]
    #[case(vec![IMAGE_HASH_1, IMAGE_HASH_3, IMAGE_HASH_2])]
    #[case(vec![IMAGE_HASH_3, IMAGE_HASH_1, IMAGE_HASH_2])]
    #[case(vec![IMAGE_HASH_1, IMAGE_HASH_2, IMAGE_HASH_3])]
    #[tokio::test]
    async fn test_latest_allowed_image_hash_is_written(
        #[case] allowed_images: Vec<AllowedDockerImageHash>,
    ) {
        let current_image = allowed_images[0].clone().image_hash;

        let cancellation_token = CancellationToken::new();
        let (sender, receiver) = watch::channel(allowed_images);
        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let write_is_called = Arc::new(Notify::new());

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            let write_is_called = write_is_called.clone();
            storage_mock
                .expect_set()
                .once()
                // Verify that the latest allowed image is written
                .with(predicate::eq(IMAGE_HASH_3))
                .returning(move |_| {
                    write_is_called.notify_one();
                    Box::pin(async { Ok(()) })
                });
        }

        let _join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token.child_token(),
            current_image.clone(),
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

    #[rstest]
    #[case::image_is_allowed(IMAGE_HASH_1.image_hash, vec![IMAGE_HASH_1])]
    // `StorageProviderError` is returned instead of `RunningImageDisallowed`.
    #[case::image_is_disallowed(IMAGE_HASH_2.image_hash, vec![IMAGE_HASH_1])]
    #[tokio::test]
    async fn test_shutdown_signal_is_sent_on_write_error(
        #[case] current_image: DockerImageHash,
        #[case] allowed_images: Vec<AllowedDockerImageHash>,
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
        let current_image = IMAGE_HASH_1.image_hash;
        let allowed_image = IMAGE_HASH_2;

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

        let join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            current_image,
            receiver,
            storage_mock,
            sender_shutdown,
        ));

        write_is_called
            .notified()
            .timeout(TEST_TIMEOUT_DURATION)
            .await
            .expect("Event loop responds within timeout.");

        let exit_reason = join_handle
            .timeout(TEST_TIMEOUT_DURATION)
            .await
            .expect("Event loop responds exits within timeout.")
            .unwrap();

        assert_matches!(exit_reason, Err(ExitError::RunningImageIsDisallowed));

        assert_matches!(
            receiver_shutdown.try_recv(),
            Ok(()),
            "Shutdown signal should be sent when running image is disallowed."
        );
    }

    #[tokio::test]
    async fn test_allowed_hashes_watcher_is_closed() {
        let cancellation_token = CancellationToken::new();
        let (sender, receiver) = watch::channel(vec![IMAGE_HASH_1]);
        drop(sender);

        let (sender_shutdown, mut receiver_shutdown) = mpsc::channel(1);

        let mut storage_mock = MockAllowedImageHashesStorage::new();
        {
            storage_mock
                .expect_set()
                .once()
                // Verify that the latest allowed image is written
                .with(predicate::eq(IMAGE_HASH_1))
                .returning(move |_| Box::pin(async { Ok(()) }));
        }

        let join_handle = tokio::spawn(monitor_allowed_image_hashes(
            cancellation_token,
            IMAGE_HASH_1.image_hash,
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
