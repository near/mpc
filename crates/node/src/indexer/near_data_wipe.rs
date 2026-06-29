//! Operator-driven one-time wipe of nearcore's data dir, triggered by a wipe
//! counter config flag.
//!
//! The node persists the last counter value it acted on in a file under
//! `home_dir` (a sibling of `data`, so it survives the wipe). When the configured
//! `wipe_near_data_counter` exceeds that value, the data dir is wiped once and the
//! new value recorded.

use std::path::Path;

/// Stores the last `wipe_near_data_counter` the node acted on.
const WIPE_COUNTER_FILE_NAME: &str = ".near_data_wipe_counter";

/// When `requested_counter` is greater than the last counter recorded on disk,
/// records it and then wipes nearcore's data dir.
pub(crate) fn wipe_near_data_if_requested(
    home_dir: &Path,
    hot_store_path: &Path,
    requested_counter: u64,
    is_archival: bool,
) -> std::io::Result<()> {
    if requested_counter == 0 {
        return Ok(());
    }
    let counter_path = home_dir.join(WIPE_COUNTER_FILE_NAME);
    let last_counter = read_last_counter(&counter_path);
    if requested_counter <= last_counter {
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            requested_counter,
            "wipe_near_data_counter bumped but node is archival; ignoring"
        );
        return Ok(());
    }

    write_last_counter(&counter_path, requested_counter)?;

    match std::fs::remove_dir_all(hot_store_path) {
        Ok(()) => tracing::info!(
            ?hot_store_path,
            requested_counter,
            "wiped nearcore data dir (wipe_near_data_counter)"
        ),
        // Fresh node: nothing to wipe.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    Ok(())
}

// Defaults to 0 if it can't read or parse file content.
fn read_last_counter(counter_path: &Path) -> u64 {
    match std::fs::read_to_string(counter_path) {
        Ok(contents) => contents.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(
                ?counter_path,
                contents,
                "unparseable near-data wipe counter, treating as 0"
            );
            0
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => {
            tracing::warn!(
                ?counter_path,
                ?err,
                "could not read wipe counter, treating as 0"
            );
            0
        }
    }
}

/// Writes and fsyncs the counter (and its parent dir) so it survives a crash
/// before the impending restart.
fn write_last_counter(counter_path: &Path, counter: u64) -> std::io::Result<()> {
    if let Some(parent) = counter_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(counter_path, counter.to_string())?;
    std::fs::File::open(counter_path)?.sync_all()?;
    if let Some(parent) = counter_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    tracing::info!(?counter_path, counter, "recorded near-data wipe counter");
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn read_recorded(home: &Path) -> Option<u64> {
        std::fs::read_to_string(home.join(WIPE_COUNTER_FILE_NAME))
            .ok()
            .map(|s| s.trim().parse().unwrap())
    }

    #[rstest]
    #[case::increases_from_zero(None, true, 1, false, false, Some(1))]
    #[case::counter_zero_is_noop(None, true, 0, false, true, None)]
    #[case::counter_equal_is_noop(Some(5), true, 5, false, true, Some(5))]
    #[case::counter_below_recorded_is_noop(Some(5), true, 3, false, true, Some(5))]
    #[case::bumped_past_recorded_wipes(Some(1), true, 2, false, false, Some(2))]
    #[case::archival_is_noop(None, true, 1, true, true, None)]
    #[case::missing_data_dir_records(None, false, 3, false, false, Some(3))]
    fn wipe_near_data_if_requested__should_wipe_only_when_counter_exceeds_recorded(
        #[case] recorded: Option<u64>,
        #[case] create_data_dir: bool,
        #[case] requested_counter: u64,
        #[case] is_archival: bool,
        #[case] expect_data_dir_exists: bool,
        #[case] expect_recorded: Option<u64>,
    ) {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = home.join("data");
        if create_data_dir {
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();
        }
        if let Some(recorded) = recorded {
            std::fs::write(home.join(WIPE_COUNTER_FILE_NAME), recorded.to_string()).unwrap();
        }

        // When
        wipe_near_data_if_requested(home, &data_dir, requested_counter, is_archival).unwrap();

        // Then
        assert_eq!(data_dir.exists(), expect_data_dir_exists);
        assert_eq!(read_recorded(home), expect_recorded);
    }
}
