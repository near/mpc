use pprof::{ProfilerGuardBuilder, Report};
use regex::Regex;
use std::{sync::LazyLock, time::Duration};
use thiserror::Error;
use tokio::task::{spawn_blocking, JoinError};

static THREAD_ID_SUFFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[_-]\d+$").unwrap());

// Use a blocklist to ensure async-signal safety.
// This prevents deadlocks if a profiling signal interrupts a thread
// while it holds internal locks in libc/libgcc (e.g., during unwinding).
// Ref: https://github.com/tikv/pprof-rs#backtrace
const SYS_CALL_BLOCK_LIST: &[&str] = &[
    "libc",
    "libgcc",
    "pthread",
    "vdso",
    // macOS (especially Apple Silicon) requires a much stricter blocklist.
    // The hardware uses Pointer Authentication (PAC), which triggers SIGTRAP
    // if a stack trace is attempted while the stack is in an inconsistent state.
    #[cfg(target_os = "macos")]
    "libsystem",
    #[cfg(target_os = "macos")]
    "libobjc",
    #[cfg(target_os = "macos")]
    "dyld",
    #[cfg(target_os = "macos")]
    "libunwind",
    #[cfg(target_os = "macos")]
    "libsystem_platform",
    #[cfg(target_os = "macos")]
    "libsystem_kernel",
    #[cfg(target_os = "macos")]
    "libsystem_malloc",
    #[cfg(target_os = "macos")]
    "libsystem_c",
    #[cfg(target_os = "macos")]
    "CoreFoundation",
    #[cfg(target_os = "macos")]
    "Foundation",
];

/// Errors returned by `profile()` and `flamegraph()`.
#[derive(Debug, Error)]
pub(crate) enum ProfileCollectionError {
    #[error("pprof profiling error")]
    Pprof(#[from] pprof::Error),
    #[error("runtime shutdown before profiling could complete")]
    RuntimeShutdown(#[from] JoinError),
}

/// Collects a pprof profile for the specified duration and frequency (Hz).
pub(crate) async fn collect_pprof(
    duration: Duration,
    frequency_hz: i32,
) -> Result<Report, ProfileCollectionError> {
    // building a profile guard is blocking, ~50ms
    let guard = spawn_blocking(move || {
        ProfilerGuardBuilder::default()
            .frequency(frequency_hz)
            .blocklist(&SYS_CALL_BLOCK_LIST)
            .build()
    })
    .await??;

    tokio::time::sleep(duration).await;

    guard
        .report()
        .frames_post_processor(move |frames| {
            frames.thread_name = normalized_thread_name(&frames.thread_name);
        })
        .build()
        .map_err(Into::into)
}

fn normalized_thread_name(thread_name: &str) -> String {
    let is_purely_numeric = thread_name.chars().all(|char| char.is_ascii_digit());

    if is_purely_numeric {
        return "".to_string();
    }

    // strip the numeric suffix and trim trailing separators
    let base = THREAD_ID_SUFFIX_REGEX
        .find(thread_name)
        .map_or(thread_name, |suffix_match| {
            &thread_name[..suffix_match.start()]
        })
        .trim_end_matches(['-', '_', ' ']);

    base.replace(['_', ' '], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_thread_name_unchanged_when_no_trailing_numeric_id_exists() {
        assert_eq!(normalized_thread_name("main"), "main");
    }

    #[test]
    fn removes_numeric_suffix_from_tokio_worker_thread_name() {
        assert_eq!(
            normalized_thread_name("tokio-runtime-worker-1"),
            "tokio-runtime-worker"
        );
    }

    #[test]
    fn replaces_underscores_with_dashes_and_strips_trailing_numeric_id() {
        assert_eq!(
            normalized_thread_name("db_connection_pool_01"),
            "db-connection-pool"
        );
    }

    #[test]
    fn replaces_spaces_with_dashes_in_multi_word_thread_names() {
        assert_eq!(
            normalized_thread_name("Search Engine Worker"),
            "Search-Engine-Worker"
        );
    }

    #[test]
    fn preserves_character_casing_while_removing_trailing_numeric_id() {
        assert_eq!(normalized_thread_name("IO-Manager-1"), "IO-Manager");
    }

    #[test]
    fn results_in_empty_string_when_input_is_entirely_numeric() {
        assert_eq!(normalized_thread_name("12345"), "");
    }

    #[test]
    fn does_not_strip_trailing_numbers_if_no_separator_is_present() {
        assert_eq!(normalized_thread_name("worker123"), "worker123");
    }

    #[test]
    fn handles_multiple_successive_separators_correctly_when_stripping_ids() {
        assert_eq!(normalized_thread_name("db-pool-_01"), "db-pool");
    }

    #[test]
    fn does_not_strip_numeric_parts_of_version_strings_at_the_start() {
        assert_eq!(normalized_thread_name("v2-engine"), "v2-engine");
    }
}
