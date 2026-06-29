//! Operator-driven one-time wipe of nearcore's data dir, triggered by a config
//! generation counter.
//!
//! The node persists the last generation it acted on in a small file under
//! `home_dir` (a sibling of `data`, so it survives the wipe). When the configured
//! `wipe_near_data_generation` exceeds that value, the data dir is wiped once and
//! the new value recorded. The operator bumps the counter to force another wipe —
//! the only lever available to a TEE node, which has no filesystem access.

use std::path::Path;

/// Stores the last `wipe_near_data_generation` the node acted on. Lives at the
/// home-dir root so it survives the wipe of the sibling `data` dir and is not
/// placed inside the mpc secret DB (`assets`).
const WIPE_GENERATION_FILE_NAME: &str = ".near_data_wipe_generation";

/// Wipes nearcore's data dir when `requested_generation` is greater than the last
/// generation recorded on disk, then records it. Must run before the store is
/// opened. No-op for archival nodes — the counter must not destroy an archive.
pub(crate) fn wipe_near_data_if_requested(
    home_dir: &Path,
    hot_store_path: &Path,
    requested_generation: u64,
    is_archival: bool,
) -> std::io::Result<()> {
    if requested_generation == 0 {
        return Ok(());
    }
    let generation_path = home_dir.join(WIPE_GENERATION_FILE_NAME);
    let last_generation = read_last_generation(&generation_path);
    if requested_generation <= last_generation {
        // Already applied this generation; bump the counter to wipe again.
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            requested_generation,
            "wipe_near_data_generation bumped but node is archival; ignoring"
        );
        return Ok(());
    }

    // Wipe first, then record the generation. A crash in between just wipes again
    // on the next startup (idempotent — the dir is re-synced); recording first
    // would risk skipping the wipe and running on stale data.
    match std::fs::remove_dir_all(hot_store_path) {
        Ok(()) => tracing::info!(
            ?hot_store_path,
            requested_generation,
            "wiped nearcore data dir (wipe_near_data_generation)"
        ),
        // Fresh node: nothing to wipe.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    write_last_generation(&generation_path, requested_generation)
}

/// Reads the last recorded generation, treating an absent or unreadable file as 0
/// so the node still starts (a pending wipe simply re-applies once).
fn read_last_generation(generation_path: &Path) -> u64 {
    match std::fs::read_to_string(generation_path) {
        Ok(contents) => contents.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(
                ?generation_path,
                contents,
                "unparseable near-data wipe generation; treating as 0"
            );
            0
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => {
            tracing::warn!(
                ?generation_path,
                ?err,
                "could not read wipe generation; treating as 0"
            );
            0
        }
    }
}

/// Writes and fsyncs the generation (and its parent dir) so it survives a crash
/// before the impending restart.
fn write_last_generation(generation_path: &Path, generation: u64) -> std::io::Result<()> {
    if let Some(parent) = generation_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(generation_path, generation.to_string())?;
    std::fs::File::open(generation_path)?.sync_all()?;
    if let Some(parent) = generation_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    tracing::info!(
        ?generation_path,
        generation,
        "recorded near-data wipe generation"
    );
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    fn read_recorded(home: &Path) -> Option<u64> {
        std::fs::read_to_string(home.join(WIPE_GENERATION_FILE_NAME))
            .ok()
            .map(|s| s.trim().parse().unwrap())
    }

    #[test]
    fn wipe_near_data_if_requested__should_wipe_and_record_when_generation_increases() {
        // Given a populated data dir, no prior generation, and a bumped counter.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, 1, false).unwrap();

        // Then
        assert!(!data_dir.exists());
        assert_eq!(read_recorded(home), Some(1));
    }

    #[test]
    fn wipe_near_data_if_requested__should_be_noop_when_generation_zero() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, 0, false).unwrap();

        // Then
        assert!(data_dir.exists());
        assert_eq!(read_recorded(home), None);
    }

    #[test]
    fn wipe_near_data_if_requested__should_be_noop_when_generation_already_applied() {
        // Given the requested generation was already recorded.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(home.join(WIPE_GENERATION_FILE_NAME), "5").unwrap();

        // When — same value as recorded.
        wipe_near_data_if_requested(home, &data_dir, 5, false).unwrap();

        // Then — not wiped again.
        assert!(data_dir.exists());
        assert_eq!(read_recorded(home), Some(5));
    }

    #[test]
    fn wipe_near_data_if_requested__should_wipe_again_when_generation_bumped_past_recorded() {
        // Given a prior wipe recorded at generation 1.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(home.join(WIPE_GENERATION_FILE_NAME), "1").unwrap();

        // When — operator bumps to 2.
        wipe_near_data_if_requested(home, &data_dir, 2, false).unwrap();

        // Then
        assert!(!data_dir.exists());
        assert_eq!(read_recorded(home), Some(2));
    }

    #[test]
    fn wipe_near_data_if_requested__should_keep_data_dir_when_archival() {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // When
        wipe_near_data_if_requested(home, &data_dir, 1, true).unwrap();

        // Then — archive is protected; no wipe, nothing recorded.
        assert!(data_dir.exists());
        assert_eq!(read_recorded(home), None);
    }

    #[test]
    fn wipe_near_data_if_requested__should_record_when_data_dir_missing() {
        // Given a fresh node with no data dir yet and a bumped counter.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");

        // When
        wipe_near_data_if_requested(home, &data_dir, 3, false).unwrap();

        // Then — no error, and the generation is recorded so it won't retry.
        assert_eq!(read_recorded(home), Some(3));
    }
}
