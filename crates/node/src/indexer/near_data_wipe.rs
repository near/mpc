//! Operator-driven one-time wipe of nearcore's data dir, triggered by a wipe
//! token config flag.
//!
//! The node persists the last token value it acted on in a file under `home_dir`
//! (a sibling of `data`, so it survives the wipe). When the configured
//! `wipe_near_data_token` is non-zero and differs from that value, the node
//! records it, then renames the data dir into a trash dir (one atomic step) and
//! deletes it. The rename makes the store vanish atomically, so a delete
//! interrupted by a crash leaves only the trash behind — which is cleaned on the
//! next startup.

use crate::home_paths::{epoch_sync_reset_marker_file, near_data_trash_dir, wipe_token_file};
use std::io::Write;
use std::path::{Component, Path};

/// Records that nearcore's epoch-sync asked for a data reset. Written just before
/// the process exits (see #3909); consumed by [`wipe_near_data_if_epoch_sync_reset`]
/// on the next startup. Best-effort: if the marker can't be written the node simply
/// loops again on restart, recoverable by an operator exactly as before this fix.
pub(crate) fn record_epoch_sync_reset_request(home_dir: &Path) {
    let marker = epoch_sync_reset_marker_file(home_dir);
    if let Err(err) = std::fs::write(&marker, b"1") {
        tracing::error!(
            ?marker,
            ?err,
            "failed to write epoch-sync data-reset marker"
        );
    }
}

/// If nearcore requested an epoch-sync data reset on a previous run, wipe the
/// chain store now — before nearcore reopens it — and clear the marker. Mirrors
/// `neard`'s `check_epoch_sync_data_reset_marker`. Reuses the same atomic
/// rename-into-trash the token wipe uses. Skipped, with a warning, on archival
/// nodes. Keyshares/secrets/config are untouched (only the store dir is moved).
pub(crate) fn wipe_near_data_if_epoch_sync_reset(
    home_dir: &Path,
    hot_store_path: &Path,
    is_archival: bool,
) -> std::io::Result<()> {
    let marker = epoch_sync_reset_marker_file(home_dir);
    if !marker.exists() {
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            "epoch-sync data-reset marker found but node is archival, ignoring"
        );
        return Ok(());
    }

    ensure_within_home(home_dir, hot_store_path)?;
    let trash_path = near_data_trash_dir(home_dir);
    remove_trash(&trash_path);
    match std::fs::rename(hot_store_path, &trash_path) {
        Ok(()) => {}
        // Already fresh (e.g. a prior crash mid-wipe already moved it) — nothing to do.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::error!(
                ?hot_store_path,
                ?err,
                "failed to move nearcore data dir aside for epoch-sync reset"
            );
            return Err(err);
        }
    }
    remove_trash(&trash_path);
    // Clear the marker only after the store is gone, so a crash mid-wipe retries.
    if let Err(err) = std::fs::remove_file(&marker)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            ?marker,
            ?err,
            "could not remove epoch-sync data-reset marker"
        );
    }
    tracing::info!(
        ?hot_store_path,
        "wiped nearcore data dir (epoch-sync data reset)"
    );
    Ok(())
}

/// Cleans any leftover wipe trash, then — if `requested_token` is non-zero and
/// differs from the last recorded value — records it and wipes the data dir.
/// Skipped, with a warning, on archival nodes.
pub(crate) fn wipe_near_data_if_requested(
    home_dir: &Path,
    hot_store_path: &Path,
    requested_token: u64,
    is_archival: bool,
) -> std::io::Result<()> {
    let trash_path = near_data_trash_dir(home_dir);
    remove_trash(&trash_path);

    // 0 is the "off" value: never wipe.
    if requested_token == 0 {
        return Ok(());
    }
    let token_path = wipe_token_file(home_dir);
    if requested_token == read_last_token(&token_path) {
        // Already applied this value, change it to any other non-zero value to wipe.
        return Ok(());
    }
    if is_archival {
        tracing::warn!(
            ?hot_store_path,
            requested_token,
            "wipe_near_data_token changed but node is archival, ignoring"
        );
        return Ok(());
    }

    // Guard against a misconfigured store.path (absolute, `..`, or the home dir
    // itself) turning the wipe into a rename/remove outside the node's data tree.
    ensure_within_home(home_dir, hot_store_path)?;

    write_last_token(&token_path, requested_token)?;

    // Move the store aside in one atomic rename, so the data dir is gone for good
    // even if the process dies before the (best-effort) delete below runs.
    match std::fs::rename(hot_store_path, &trash_path) {
        Ok(()) => {}
        // Fresh node: nothing to wipe.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            tracing::error!(
                ?hot_store_path,
                requested_token,
                ?err,
                "failed to move nearcore data dir aside for wiping; the data was NOT wiped and \
                 the wipe will NOT be retried automatically (token already recorded) — fix the \
                 cause and set wipe_near_data_token to a new value to retry"
            );
            return Err(err);
        }
    }
    remove_trash(&trash_path);
    tracing::info!(
        ?hot_store_path,
        requested_token,
        "wiped nearcore data dir (wipe_near_data_token)"
    );
    Ok(())
}

/// Best-effort recursive delete of the wipe trash dir. Never fatal.
fn remove_trash(trash_path: &Path) {
    if let Err(err) = std::fs::remove_dir_all(trash_path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            ?trash_path,
            ?err,
            "could not delete near-data wipe trash dir, will retry on next startup"
        );
    }
}

/// Rejects a wipe target that is not a normal subdirectory of `home_dir` (an
/// absolute path, a `..` traversal, `.`, or `home_dir` itself), so a misconfigured
/// store.path can't make the wipe destructive outside the node's data tree.
///
/// This does not resolve symlinks. Safe because the node never creates
/// symlinks under `home_dir` and `remove_dir_all` unlinks symlinks instead of
/// following them.
fn ensure_within_home(home_dir: &Path, hot_store_path: &Path) -> std::io::Result<()> {
    let within = match hot_store_path.strip_prefix(home_dir) {
        Ok(relative) => {
            let mut components = relative.components().peekable();
            // Non-empty (not `home_dir` itself) and every component a plain name.
            components.peek().is_some() && components.all(|c| matches!(c, Component::Normal(_)))
        }
        Err(_) => false,
    };
    if within {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to wipe {hot_store_path:?}: not a subdirectory of {home_dir:?}"),
        ))
    }
}

fn read_last_token(token_path: &Path) -> u64 {
    match std::fs::read_to_string(token_path) {
        Ok(contents) => contents.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(
                ?token_path,
                contents,
                "unparseable near-data wipe token, treating as 0"
            );
            0
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => {
            tracing::warn!(
                ?token_path,
                ?err,
                "could not read wipe token, treating as 0"
            );
            0
        }
    }
}

/// Atomically records the token: write a temp file, fsync it, then `rename` it into
/// place and fsync the parent dir. The old file stays intact until the rename, so a
/// crash mid-write can't leave a truncated token that reads as 0 and triggers an
/// extra wipe next boot.
fn write_last_token(token_path: &Path, token: u64) -> std::io::Result<()> {
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = token_path.with_extension("tmp");
    {
        let mut tmp = std::fs::File::create(&tmp_path)?;
        tmp.write_all(token.to_string().as_bytes())?;
        tmp.sync_all()?;
    }
    std::fs::rename(&tmp_path, token_path)?;
    // fsync the dir so the rename (the durable record) survives a crash.
    if let Some(parent) = token_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    tracing::info!(?token_path, token, "recorded near-data wipe token");
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::home_paths::{near_data_dir, secrets_file};
    use rstest::rstest;

    fn read_recorded(home: &Path) -> Option<u64> {
        std::fs::read_to_string(wipe_token_file(home))
            .ok()
            .map(|s| s.trim().parse().unwrap())
    }

    fn marker_exists(home: &Path) -> bool {
        epoch_sync_reset_marker_file(home).exists()
    }

    #[rstest]
    #[case::differs_from_zero_wipes(None, true, 1, false, false, Some(1))]
    #[case::token_zero_is_noop(None, true, 0, false, true, None)]
    #[case::token_equal_is_noop(Some(5), true, 5, false, true, Some(5))]
    #[case::differs_above_recorded_wipes(Some(1), true, 2, false, false, Some(2))]
    #[case::differs_below_recorded_wipes(Some(5), true, 3, false, false, Some(3))]
    #[case::differs_after_max_wipes(Some(u64::MAX), true, 1, false, false, Some(1))]
    #[case::archival_is_noop(None, true, 1, true, true, None)]
    #[case::missing_data_dir_records(None, false, 3, false, false, Some(3))]
    fn wipe_near_data_if_requested__should_wipe_when_token_is_nonzero_and_differs(
        #[case] recorded: Option<u64>,
        #[case] create_data_dir: bool,
        #[case] requested_token: u64,
        #[case] is_archival: bool,
        #[case] expect_data_dir_exists: bool,
        #[case] expect_recorded: Option<u64>,
    ) {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = near_data_dir(home);
        if create_data_dir {
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();
        }
        if let Some(recorded) = recorded {
            std::fs::write(wipe_token_file(home), recorded.to_string()).unwrap();
        }

        // When
        wipe_near_data_if_requested(home, &data_dir, requested_token, is_archival).unwrap();

        // Then
        assert_eq!(data_dir.exists(), expect_data_dir_exists);
        assert_eq!(read_recorded(home), expect_recorded);
    }

    #[test]
    fn wipe_near_data_if_requested__should_succeed_when_trash_cleanup_fails() {
        // Given a regular file where the data dir is expected: the atomic rename
        // moves it aside, but deleting that file as a directory fails.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let not_a_dir = near_data_dir(home);
        std::fs::write(&not_a_dir, b"not a directory").unwrap();

        // When
        let result = wipe_near_data_if_requested(home, &not_a_dir, 1, false);

        // Then — the data path is gone and the token recorded; the failed trash
        // cleanup is non-fatal (retried on the next startup), so the wipe succeeds.
        result.unwrap();
        assert!(!not_a_dir.exists());
        assert_eq!(read_recorded(home), Some(1));
    }

    #[test]
    fn wipe_near_data_if_requested__should_clean_leftover_trash_on_startup() {
        // Given trash left by an earlier interrupted wipe, and no wipe requested now.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let trash = near_data_trash_dir(home);
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("leftover"), b"stale").unwrap();

        // When
        wipe_near_data_if_requested(home, &near_data_dir(home), 0, false).unwrap();

        // Then
        assert!(!trash.exists());
    }

    #[rstest]
    #[case::normal_subdir("data", true)]
    #[case::nested_subdir("a/b", true)]
    #[case::home_itself("", false)]
    #[case::current_dir(".", false)]
    #[case::parent_traversal("../escape", false)]
    #[case::absolute("/escape", false)]
    fn ensure_within_home__should_reject_targets_outside_home(
        #[case] sub: &str,
        #[case] expect_ok: bool,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let hot_store_path = home.join(sub);
        assert_eq!(ensure_within_home(home, &hot_store_path).is_ok(), expect_ok);
    }

    #[rstest]
    #[case::marker_present_wipes_and_clears(true, true, false, false, false)]
    #[case::no_marker_is_noop(false, true, false, true, false)]
    #[case::archival_keeps_data_and_marker(true, true, true, true, true)]
    #[case::missing_data_dir_clears_marker(true, false, false, false, false)]
    fn wipe_near_data_if_epoch_sync_reset__should_wipe_and_clear_only_when_marker_present(
        #[case] create_marker: bool,
        #[case] create_data_dir: bool,
        #[case] is_archival: bool,
        #[case] expect_data_dir_exists: bool,
        #[case] expect_marker_exists: bool,
    ) {
        // Given
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = near_data_dir(home);
        if create_data_dir {
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();
        }
        if create_marker {
            record_epoch_sync_reset_request(home);
        }

        // When
        wipe_near_data_if_epoch_sync_reset(home, &data_dir, is_archival).unwrap();

        // Then
        assert_eq!(data_dir.exists(), expect_data_dir_exists);
        assert_eq!(marker_exists(home), expect_marker_exists);
    }

    #[test]
    fn epoch_sync_reset__should_wipe_only_the_store_and_preserve_siblings_across_restart() {
        // Given a synced node: a chain store plus a keyshare-like sibling file, and
        // nearcore having requested a reset (recorded at shutdown, as in `real.rs`).
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let data_dir = near_data_dir(home);
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("CURRENT"), b"db-content").unwrap();
        let keyshare = secrets_file(home);
        std::fs::write(&keyshare, b"keyshare-secret").unwrap();
        record_epoch_sync_reset_request(home);

        // When the node restarts and runs the startup wipe.
        wipe_near_data_if_epoch_sync_reset(home, &data_dir, false).unwrap();

        // Then only the chain store is gone; the marker is cleared and the keyshare survives.
        assert!(!data_dir.exists());
        assert!(!marker_exists(home));
        assert_eq!(std::fs::read(&keyshare).unwrap(), b"keyshare-secret");
    }

    #[test]
    fn wipe_near_data_if_epoch_sync_reset__should_error_when_store_path_escapes_home() {
        // Given a reset marker but a misconfigured store path outside the home tree.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        record_epoch_sync_reset_request(home);
        let escaping = home.join("../escape");

        // When / Then — the path guard rejects it and the data is left untouched.
        assert!(wipe_near_data_if_epoch_sync_reset(home, &escaping, false).is_err());
    }
}
