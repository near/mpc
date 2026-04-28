use crate::common;

use backon::{ConstantBuilder, Retryable};

/// Tests that non-participant MPC nodes automatically submit their TEE
/// attestations to the contract after startup.
///
/// Setup: 4 nodes started, but only 2 are initial participants. The other 2
/// should submit attestations on their own. We verify all 4 appear in the
/// contract's TEE accounts list.
#[tokio::test]
async fn test_submit_participant_info() {
    let (cluster, _running) =
        common::must_setup_cluster(common::SUBMIT_PARTICIPANT_INFO_PORT_SEED, |c| {
            c.num_nodes = 4;
            c.initial_participant_indices = vec![0, 1];
        })
        .await;

    // Poll until all 4 nodes have TEE attestations in the contract.
    (|| async {
        let tee_accounts = cluster.get_tee_accounts().await?;
        anyhow::ensure!(
            tee_accounts.len() == 4,
            "only {}/4 nodes have submitted attestations",
            tee_accounts.len()
        );
        tracing::info!(
            count = tee_accounts.len(),
            "all nodes submitted attestations"
        );
        Ok::<_, anyhow::Error>(())
    })
    // 30s deadline: 30_000ms / 500ms = 60 attempts
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(60),
    )
    .await
    .expect("timed out waiting for all 4 nodes to submit attestations");
}
