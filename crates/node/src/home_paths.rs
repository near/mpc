//! Single source of truth for the node's `home_dir`-relative paths.

use std::path::{Path, PathBuf};

/// nearcore's chain store. This is the default location, `store.path` in the
/// near config can override where the store actually lives.
pub fn near_data_dir(home_dir: &Path) -> PathBuf {
    home_dir.join("data")
}

/// SecretDB: triples and presignatures.
pub fn assets_dir(home_dir: &Path) -> PathBuf {
    home_dir.join("assets")
}

/// Directory holding the permanent keyshares, one file per key epoch.
pub fn permanent_keys_dir(home_dir: &Path) -> PathBuf {
    home_dir.join("permanent_keys")
}

/// Hard link to the current keyshare in [`permanent_keys_dir`].
pub fn permanent_key_link(home_dir: &Path) -> PathBuf {
    home_dir.join("key")
}

/// Local secrets (`secret_store_key`, responder keys, ...).
pub fn secrets_file(home_dir: &Path) -> PathBuf {
    home_dir.join("secrets.json")
}

pub fn backup_encryption_key_file(home_dir: &Path) -> PathBuf {
    home_dir.join("backup_encryption_key.hex")
}

/// Records the last `wipe_near_data_token` the node acted on.
pub fn wipe_token_file(home_dir: &Path) -> PathBuf {
    home_dir.join(".near_data_wipe_token")
}

/// Holds the data dir mid-wipe: the wipe renames the store here in one atomic
/// step, then deletes it. Leftovers from an interrupted delete are cleaned on
/// the next startup.
pub fn near_data_trash_dir(home_dir: &Path) -> PathBuf {
    home_dir.join(".near_data_trash")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    /// Tripwire: relocating any of these under the wipe target turns the
    /// near-data wipe into a keyshare-destroyer. Each must call the same path
    /// helper the runtime uses, so the assertion tracks the real layout.
    #[test]
    fn near_data_dir__should_be_disjoint_from_protected_paths() {
        // Given
        let home = Path::new("/home/mpc");
        let wipe_target = near_data_dir(home);
        let protected = [
            assets_dir(home),
            permanent_keys_dir(home),
            permanent_key_link(home),
            secrets_file(home),
            backup_encryption_key_file(home),
            wipe_token_file(home),
        ];

        // Then
        for path in protected {
            assert!(
                !path.starts_with(&wipe_target),
                "{path:?} is inside the near-data wipe target {wipe_target:?}; \
                 a wipe would destroy it"
            );
        }
    }

    /// The wipe renames the data dir into the trash dir, which requires the two to
    /// be siblings — neither can be nested inside the other.
    #[test]
    fn near_data_trash_dir__should_be_a_sibling_of_the_wipe_target() {
        // Given
        let home = Path::new("/home/mpc");
        let data = near_data_dir(home);
        let trash = near_data_trash_dir(home);

        // Then
        assert!(!trash.starts_with(&data), "{trash:?} is inside {data:?}");
        assert!(!data.starts_with(&trash), "{data:?} is inside {trash:?}");
    }
}
