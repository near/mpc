//! Mirrors `neard`'s epoch-sync-data-reset recovery for the in-process node.
//!
//! When nearcore detects its chain data is stale (beyond the sync horizon) it
//! emits [`ShutdownReason::EpochSyncDataReset`], asking the host to wipe the
//! data dir and re-sync on restart. `neard` does this via a marker file.

use near_client::client_actor::ShutdownReason;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};

const RESET_MARKER_FILE_NAME: &str = ".EPOCH_SYNC_DATA_RESET";

/// Deletes nearcore's data dir if a previous run left a reset marker. No-op for
/// archival nodes. Must run before the store is opened.
pub(crate) fn wipe_data_dir_if_reset_requested(
    hot_store_path: &Path,
    is_archival: bool,
) -> std::io::Result<()> {
    let marker_path = hot_store_path.join(RESET_MARKER_FILE_NAME);
    if !marker_path.try_exists()? {
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            "epoch sync reset marker found but node is archival; ignoring"
        );
        return Ok(());
    }
    tracing::info!(
        ?hot_store_path,
        "epoch sync reset marker found; wiping data dir"
    );
    std::fs::remove_dir_all(hot_store_path)
}

/// Writes the reset marker so the next startup wipes the data dir.
pub(crate) fn request_data_dir_reset(hot_store_path: &Path) -> std::io::Result<()> {
    let marker_path = hot_store_path.join(RESET_MARKER_FILE_NAME);
    std::fs::create_dir_all(hot_store_path)?;
    std::fs::write(&marker_path, b"")?;
    // fsync the file and its directory so the marker survives a crash before
    // the impending restart.
    std::fs::File::open(&marker_path)?.sync_all()?;
    std::fs::File::open(hot_store_path)?.sync_all()?;
    tracing::info!(?marker_path, "epoch sync reset marker written");
    Ok(())
}

/// Awaits [`ShutdownReason::EpochSyncDataReset`] from nearcore and signals
/// `exit_signal` to exit; when `auto_reset`, also writes the marker so the next
/// startup wipes the data dir.
pub(crate) async fn await_and_handle_reset(
    mut reset_signal: broadcast::Receiver<ShutdownReason>,
    hot_store_path: PathBuf,
    auto_reset: bool,
    exit_signal: mpsc::Sender<()>,
) {
    loop {
        match reset_signal.recv().await {
            Ok(ShutdownReason::EpochSyncDataReset) => {
                if auto_reset {
                    if let Err(err) = request_data_dir_reset(&hot_store_path) {
                        tracing::error!(?err, "failed to write epoch sync reset marker");
                    }
                } else {
                    tracing::error!(
                        ?hot_store_path,
                        "nearcore reported stale chain data but auto-reset is disabled \
                         (indexer.reset_stale_near_data=false); delete the data dir manually \
                         and restart, or enable auto-reset"
                    );
                }
                let _ = exit_signal.send(()).await;
                return;
            }
            Ok(_) => {}
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn wipe_data_dir_if_reset_requested__should_remove_data_dir_when_marker_present() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();
        request_data_dir_reset(&data_dir).unwrap();

        // When
        wipe_data_dir_if_reset_requested(&data_dir, false).unwrap();

        // Then
        assert!(!data_dir.exists());
    }

    #[test]
    fn wipe_data_dir_if_reset_requested__should_keep_data_dir_when_archival() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        request_data_dir_reset(&data_dir).unwrap();

        // When
        wipe_data_dir_if_reset_requested(&data_dir, true).unwrap();

        // Then
        assert!(data_dir.exists());
    }

    #[test]
    fn wipe_data_dir_if_reset_requested__should_be_noop_when_marker_absent() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // When
        wipe_data_dir_if_reset_requested(&data_dir, false).unwrap();

        // Then
        assert!(data_dir.exists());
    }

    #[tokio::test]
    async fn await_and_handle_reset__should_write_marker_and_signal_on_reset() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let (reset_tx, reset_rx) = broadcast::channel(16);
        let (exit_tx, mut exit_rx) = mpsc::channel(1);
        reset_tx.send(ShutdownReason::EpochSyncDataReset).unwrap();

        // When
        await_and_handle_reset(reset_rx, data_dir.clone(), true, exit_tx).await;

        // Then
        assert!(data_dir.join(RESET_MARKER_FILE_NAME).exists());
        assert!(exit_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn await_and_handle_reset__should_signal_without_marker_when_auto_reset_disabled() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let (reset_tx, reset_rx) = broadcast::channel(16);
        let (exit_tx, mut exit_rx) = mpsc::channel(1);
        reset_tx.send(ShutdownReason::EpochSyncDataReset).unwrap();

        // When
        await_and_handle_reset(reset_rx, data_dir.clone(), false, exit_tx).await;

        // Then
        assert!(!data_dir.join(RESET_MARKER_FILE_NAME).exists());
        assert!(exit_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn await_and_handle_reset__should_return_without_signal_when_channel_closes() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let (reset_tx, reset_rx) = broadcast::channel::<ShutdownReason>(16);
        let (exit_tx, mut exit_rx) = mpsc::channel(1);
        drop(reset_tx);

        // When
        await_and_handle_reset(reset_rx, data_dir.clone(), true, exit_tx).await;

        // Then
        assert!(!data_dir.join(RESET_MARKER_FILE_NAME).exists());
        assert!(exit_rx.try_recv().is_err());
    }
}
