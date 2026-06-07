use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use crate::common;

/// Verifies that mpc-node's SIGTERM handler initiates a graceful shutdown
/// instead of letting the OS default-terminate the process.
///
/// Would fail under revert: without the handler in `crates/node/src/run.rs`,
/// SIGTERM hits the process with no handler installed and the OS terminates
/// the process directly. `status.signal()` is then `Some(15)` (SIGTERM) and
/// `status.code()` is `None`, which the assertion below catches. With the
/// handler installed the process exits via `main`'s normal return path,
/// `status.code()` is `Some(_)`, and the assertion passes.
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

    // Then: the process exited via its own main(), not by OS signal.
    assert!(
        status.code().is_some(),
        "mpc-node was terminated by signal {:?} instead of exiting cleanly via the SIGTERM handler",
        status.signal()
    );
}
