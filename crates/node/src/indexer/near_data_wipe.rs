//! Operator-driven one-shot wipe of nearcore's data dir.
//!
//! When `indexer.wipe_near_data_once` is set, the data dir (`home_dir/data`) is
//! deleted once on startup and a sentinel is written so the wipe does not repeat.
//! The operator removes the sentinel to arm another wipe.

use std::path::Path;

/// Marks that a one-shot wipe has already run. Lives at the home-dir root so it
/// survives the wipe of the sibling `data` dir and is not placed inside the mpc
/// secret DB (`assets`).
const WIPE_DONE_SENTINEL_FILE_NAME: &str = ".near_data_wiped";

/// Wipes nearcore's data dir once when `wipe_once` is set and no sentinel exists,
/// then writes the sentinel. Must run before the store is opened. No-op for
/// archival nodes — the flag must not destroy an archive.
pub(crate) fn wipe_near_data_if_requested(
    home_dir: &Path,
    hot_store_path: &Path,
    wipe_once: bool,
    is_archival: bool,
) -> std::io::Result<()> {
    if !wipe_once {
        return Ok(());
    }
    let sentinel_path = home_dir.join(WIPE_DONE_SENTINEL_FILE_NAME);
    if sentinel_path.try_exists()? {
        // Already wiped for this arming; remove the sentinel to wipe again.
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            "wipe_near_data_once is set but node is archival, ignoring"
        );
        return Ok(());
    }

    // Wipe first, then persist the sentinel. A crash in between just wipes again on
    // the next startup (idempotent — the dir is re-synced); writing the sentinel
    // first would risk skipping the wipe and running on stale data.
    match std::fs::remove_dir_all(hot_store_path) {
        Ok(()) => tracing::info!(
            ?hot_store_path,
            "wiped nearcore data dir (wipe_near_data_once)"
        ),
        // Fresh node: nothing to wipe.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    write_sentinel(&sentinel_path)
}

/// Writes and fsyncs the sentinel (and its parent dir) so it survives a crash
/// before the impending restart.
fn write_sentinel(sentinel_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = sentinel_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(sentinel_path, b"")?;
    std::fs::File::open(sentinel_path)?.sync_all()?;
    if let Some(parent) = sentinel_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    tracing::info!(?sentinel_path, "wrote near-data wipe sentinel");
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn wipe_near_data_if_requested__should_wipe_and_write_sentinel_when_flag_set() {
        // Given a populated data dir and the flag set.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, true, false).unwrap();

        // Then
        assert!(!data_dir.exists());
        assert!(home.join(WIPE_DONE_SENTINEL_FILE_NAME).exists());
    }

    #[test]
    fn wipe_near_data_if_requested__should_be_noop_when_flag_unset() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, false, false).unwrap();

        // Then
        assert!(data_dir.exists());
        assert!(!home.join(WIPE_DONE_SENTINEL_FILE_NAME).exists());
    }

    #[test]
    fn wipe_near_data_if_requested__should_be_noop_when_sentinel_present() {
        // Given a sentinel from a previous wipe.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(home.join(WIPE_DONE_SENTINEL_FILE_NAME), b"").unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, true, false).unwrap();

        // Then — not wiped again.
        assert!(data_dir.exists());
    }

    #[test]
    fn wipe_near_data_if_requested__should_keep_data_dir_when_archival() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, true, true).unwrap();

        // Then — archive is protected; no wipe, no sentinel.
        assert!(data_dir.exists());
        assert!(!home.join(WIPE_DONE_SENTINEL_FILE_NAME).exists());
    }

    #[test]
    fn wipe_near_data_if_requested__should_write_sentinel_when_data_dir_missing() {
        // Given a fresh node with no data dir yet.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");

        // When
        wipe_near_data_if_requested(home, &data_dir, true, false).unwrap();

        // Then — no error, and the sentinel is written so it won't retry.
        assert!(home.join(WIPE_DONE_SENTINEL_FILE_NAME).exists());
    }
}
