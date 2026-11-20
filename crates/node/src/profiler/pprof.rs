use inferno::flamegraph::{self, Options};
use itertools::Itertools;
use pprof::{Frames, ProfilerGuardBuilder, Report};
use regex::Regex;
use std::{collections::HashMap, io, iter, sync::LazyLock, time::Duration};
use thiserror::Error;
use tokio::task::{JoinError, spawn_blocking};

static THREAD_ID_SUFFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[_-]\d+$").unwrap());

macro_rules! define_block_list {
    (common: [$($common:expr_2021),*], macos_extra: [$($macos:expr_2021),*]) => {
        &[
            $($common),*,
            // macOS specific entries
            $( #[cfg(target_os = "macos")] $macos ),*
        ]
    };
}

/// Use a blocklist to ensure async-signal safety.
/// This prevents deadlocks if a profiling signal interrupts a thread
/// while it holds internal locks in libc/libgcc (e.g., during unwinding).
/// Ref: <https://github.com/tikv/pprof-rs#backtrace>
const SYS_CALL_BLOCK_LIST: &[&str] = define_block_list! {
    common: ["libc", "libgcc", "pthread", "vdso"],
    // macOS, especially Apple Silicon, requires a much stricter blocklist.
    // Apple's ARM CPUs use Pointer Authentication (PAC), which triggers SIGTRAP
    // if a stack trace is attempted while the stack is in an inconsistent state.
    macos_extra: [
        "libsystem",
        "libobjc",
        "dyld",
        "libunwind",
        "libsystem_platform",
        "libsystem_kernel",
        "libsystem_malloc",
        "libsystem_c",
        "CoreFoundation",
        "Foundation"
    ]
};

/// Collects a pprof profile for the specified duration and frequency (Hz).
pub(super) async fn collect_pprof(
    duration: Duration,
    frequency_hz: i32,
) -> Result<Report, ProfileCollectionError> {
    // building a profile guard is blocking, ~50ms
    let guard = spawn_blocking(move || {
        ProfilerGuardBuilder::default()
            .frequency(frequency_hz)
            .blocklist(SYS_CALL_BLOCK_LIST)
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

// TODO(#5275): switch back to pprof's own flamegraph rendering once it uses inferno 0.12
pub(super) fn write_flamegraph(report: &Report, writer: impl io::Write) -> io::Result<()> {
    let stacks = collapsed_stacks(&report.data);
    flamegraph::from_reader(&mut Options::default(), stacks.as_bytes(), writer)
}

fn collapsed_stacks(samples: &HashMap<Frames, isize>) -> String {
    samples
        .iter()
        .map(|(stack, count)| {
            let thread = iter::once(stack.thread_name_or_id());
            let symbols = stack.frames.iter().flatten().rev().map(ToString::to_string);
            format!("{} {count}", thread.chain(symbols).join(";"))
        })
        .join("\n")
}

#[derive(Debug, Error)]
pub(super) enum ProfileCollectionError {
    #[error("pprof profiling error")]
    Pprof(#[from] pprof::Error),
    #[error("runtime shutdown before profiling could complete")]
    RuntimeShutdown(#[from] JoinError),
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
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use pprof::Symbol;
    use std::time::SystemTime;

    fn symbol(name: &str) -> Symbol {
        Symbol {
            name: Some(name.into()),
            addr: None,
            lineno: None,
            filename: None,
        }
    }

    #[test]
    fn collapsed_stacks__should_list_frames_from_outermost_to_innermost() {
        // Given
        let stack = Frames {
            frames: vec![vec![symbol("leaf"), symbol("mid")], vec![symbol("root")]],
            thread_name: "worker".into(),
            thread_id: 0,
            sample_timestamp: SystemTime::UNIX_EPOCH,
        };

        // When
        let collapsed_stacks = collapsed_stacks(&HashMap::from([(stack, 3)]));

        // Then
        assert_eq!(collapsed_stacks, "worker;root;mid;leaf 3");
    }

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
