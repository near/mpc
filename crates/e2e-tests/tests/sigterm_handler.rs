use std::os::unix::process::ExitStatusExt;
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

    // Then: the process exited cleanly with code 0.
    assert!(
        status.success(),
        "mpc-node did not exit cleanly after SIGTERM: code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
}
