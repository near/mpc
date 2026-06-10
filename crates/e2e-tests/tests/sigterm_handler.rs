use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::time::Duration;

use crate::common;

/// Verifies that mpc-node's SIGTERM handler drives a clean graceful shutdown
/// (exit code 0), not just any process termination.
///
/// Would fail under revert in two ways:
/// - Without the SIGTERM handler at all, the OS default-terminates the
///   process and `status.success()` is false (`code()` is `None`,
///   `signal()` is `Some(15)`).
/// - With a handler that returns an error from `run_mpc_node` on signal
///   shutdown (the previous behavior, before the signal/image-hash split),
///   `status.success()` is also false (exit code 1).
#[tokio::test(flavor = "multi_thread")]
#[expect(non_snake_case)]
async fn sigterm_handler__should_exit_cleanly_instead_of_default_terminating() {
    // Given: a running cluster.
    let (mut cluster, _running) =
        common::must_setup_cluster(common::SIGTERM_HANDLER_PORT_SEED, |_| {}).await;

    // When: SIGTERM is delivered to node 0 with a 30s grace period.
    let status = cluster
        .terminate_node_with_sigterm(0, Duration::from_secs(30))
        .expect("node did not exit within the SIGTERM grace period");

    // Then: the process exited cleanly with code 0. On failure, inline the
    // tails of node 0's stdout/stderr so the panic message carries
    // mpc-node's last log lines — tracing → stdout, panics/eprintln →
    // stderr. The test's tempdir is cleaned on exit, so without this dump
    // CI only sees the exit signal and we can't tell e.g. a tokio-task
    // panic that aborted the process during shutdown from a clean failure.
    let home = cluster.nodes[0].home_dir();
    let stdout_tail = read_log_tail(&home.join("stdout.log"), 16_384);
    let stderr_tail = read_log_tail(&home.join("stderr.log"), 16_384);
    assert!(
        status.success(),
        "mpc-node did not exit cleanly after SIGTERM: code={:?} signal={:?}\n\
         --- last 16KB of node 0 stdout.log (mpc-node tracing) ---\n{stdout_tail}\n\
         --- end stdout.log ---\n\
         --- last 16KB of node 0 stderr.log (panic backtraces) ---\n{stderr_tail}\n\
         --- end stderr.log ---",
        status.code(),
        status.signal()
    );
}

/// Best-effort read of the last `max_bytes` of a log file. Returns a
/// synthetic placeholder string if the file can't be opened/read.
fn read_log_tail(path: &Path, max_bytes: usize) -> String {
    let Ok(mut f) = std::fs::File::open(path) else {
        return format!("(could not open {})", path.display());
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let skip = len.saturating_sub(max_bytes as u64);
    if f.seek(SeekFrom::Start(skip)).is_err() {
        return format!("(seek failed on {})", path.display());
    }
    let mut buf = Vec::with_capacity(max_bytes);
    if f.read_to_end(&mut buf).is_err() {
        return format!("(read failed on {})", path.display());
    }
    String::from_utf8_lossy(&buf).into_owned()
}
