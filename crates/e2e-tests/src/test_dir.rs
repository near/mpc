use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

const HOME_BASE_ENV: &str = "E2E_HOME_BASE";
const KEEP_ENV: &str = "E2E_KEEP_TMP";
const DIR_PREFIX: &str = "mpc-e2e-";

/// Root directory holding one test's artifacts: the `mpc-node` home dirs with
/// their configs, RocksDB data, `stdout.log` and `stderr.log`.
///
/// Deleted when the last clone drops, unless the test failed (dropped while
/// panicking, or [`TestDir::keep`] was called) or `E2E_KEEP_TMP` asks for it.
/// `E2E_HOME_BASE` overrides the parent directory.
#[derive(Clone)]
pub struct TestDir {
    inner: Arc<TestDirState>,
}

struct TestDirState {
    temp: tempfile::TempDir,
    keep_artifacts: KeepArtifacts,
    keep_requested: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeepArtifacts {
    Always,
    OnFailure,
    Never,
}

impl TestDir {
    /// Creates the directory under `home_base`, falling back to `E2E_HOME_BASE`
    /// and then to the system temp dir.
    pub fn new(home_base: Option<&Path>) -> anyhow::Result<Self> {
        Self::with_keep_artifacts(home_base, keep_artifacts_from_env())
    }

    fn with_keep_artifacts(
        home_base: Option<&Path>,
        keep_artifacts: KeepArtifacts,
    ) -> anyhow::Result<Self> {
        let base = home_base
            .map(PathBuf::from)
            .or_else(|| std::env::var_os(HOME_BASE_ENV).map(PathBuf::from));
        let mut builder = tempfile::Builder::new();
        let builder = builder.prefix(DIR_PREFIX);
        let temp = match &base {
            Some(base) => {
                std::fs::create_dir_all(base)
                    .with_context(|| format!("failed to create {}", base.display()))?;
                builder.tempdir_in(base)
            }
            None => builder.tempdir(),
        }
        .context("failed to create e2e test directory")?;

        tracing::info!(dir = %temp.path().display(), "created e2e test directory");
        Ok(Self {
            inner: Arc::new(TestDirState {
                temp,
                keep_artifacts,
                keep_requested: AtomicBool::new(false),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        self.inner.temp.path()
    }

    /// Keeps the directory after the test ends, unless `E2E_KEEP_TMP` is falsy.
    pub fn keep(&self) {
        self.inner.keep_requested.store(true, Ordering::Relaxed);
    }
}

impl Drop for TestDirState {
    fn drop(&mut self) {
        let keep = match self.keep_artifacts {
            KeepArtifacts::Always => true,
            KeepArtifacts::Never => false,
            KeepArtifacts::OnFailure => {
                self.keep_requested.load(Ordering::Relaxed) || std::thread::panicking()
            }
        };
        if !keep {
            return;
        }
        self.temp.disable_cleanup(true);
        // Printed as well as logged: the captured test output is where a
        // developer looks after a failure, whatever the `tracing` filter is.
        let path = self.temp.path().display();
        eprintln!("e2e artifacts preserved in {path}");
        tracing::warn!(dir = %path, "e2e artifacts preserved");
    }
}

fn keep_artifacts_from_env() -> KeepArtifacts {
    keep_artifacts_from(std::env::var(KEEP_ENV).ok().as_deref())
}

fn keep_artifacts_from(value: Option<&str>) -> KeepArtifacts {
    match value
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") => KeepArtifacts::OnFailure,
        Some("0" | "false" | "no" | "off") => KeepArtifacts::Never,
        Some(_) => KeepArtifacts::Always,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::panic::AssertUnwindSafe;

    use super::*;

    /// Pins the policy so an ambient `E2E_KEEP_TMP` cannot decide the outcome.
    fn test_dir_in(base: &Path, keep_artifacts: KeepArtifacts) -> TestDir {
        TestDir::with_keep_artifacts(Some(base), keep_artifacts).unwrap()
    }

    #[test]
    fn test_dir__should_delete_the_directory_when_the_test_passed() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let dir = test_dir_in(base.path(), KeepArtifacts::OnFailure);
        let path = dir.path().to_path_buf();

        // When
        drop(dir);

        // Then
        assert!(!path.exists(), "{} still exists", path.display());
    }

    #[test]
    fn test_dir__should_preserve_the_directory_when_dropped_while_panicking() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let base_path = base.path().to_path_buf();

        // When
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let dir = test_dir_in(&base_path, KeepArtifacts::OnFailure);
            std::panic::panic_any(dir.path().to_path_buf());
        }))
        .unwrap_err();

        // Then
        let path = *panic.downcast::<PathBuf>().unwrap();
        assert!(path.exists(), "{} was deleted", path.display());
    }

    #[test]
    fn test_dir__should_preserve_the_directory_when_keep_was_requested() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let dir = test_dir_in(base.path(), KeepArtifacts::OnFailure);
        let path = dir.path().to_path_buf();

        // When
        dir.keep();
        drop(dir);

        // Then
        assert!(path.exists(), "{} was deleted", path.display());
    }

    #[test]
    fn test_dir__should_preserve_the_directory_when_keeping_always() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let dir = test_dir_in(base.path(), KeepArtifacts::Always);
        let path = dir.path().to_path_buf();

        // When
        drop(dir);

        // Then
        assert!(path.exists(), "{} was deleted", path.display());
    }

    #[test]
    fn test_dir__should_delete_the_directory_when_keeping_never_despite_a_keep_request() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let dir = test_dir_in(base.path(), KeepArtifacts::Never);
        let path = dir.path().to_path_buf();

        // When
        dir.keep();
        drop(dir);

        // Then
        assert!(!path.exists(), "{} still exists", path.display());
    }

    #[test]
    fn test_dir__should_delete_the_directory_only_once_all_clones_are_dropped() {
        // Given
        let base = tempfile::tempdir().unwrap();
        let dir = test_dir_in(base.path(), KeepArtifacts::OnFailure);
        let path = dir.path().to_path_buf();
        let clone = dir.clone();

        // When
        drop(dir);

        // Then
        assert!(
            path.exists(),
            "{} deleted while a clone lives",
            path.display()
        );
        drop(clone);
        assert!(!path.exists(), "{} still exists", path.display());
    }

    #[test]
    fn keep_artifacts_from__should_map_the_env_var_to_a_policy() {
        // Given
        let cases = [
            (None, KeepArtifacts::OnFailure),
            (Some(""), KeepArtifacts::OnFailure),
            (Some("0"), KeepArtifacts::Never),
            (Some("false"), KeepArtifacts::Never),
            (Some("FALSE"), KeepArtifacts::Never),
            (Some("no"), KeepArtifacts::Never),
            (Some("No"), KeepArtifacts::Never),
            (Some("off"), KeepArtifacts::Never),
            (Some("1"), KeepArtifacts::Always),
            (Some(" true "), KeepArtifacts::Always),
        ];

        for (value, expected) in cases {
            // When
            let policy = keep_artifacts_from(value);

            // Then
            assert_eq!(policy, expected, "for {value:?}");
        }
    }
}
