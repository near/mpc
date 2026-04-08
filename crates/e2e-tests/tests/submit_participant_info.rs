mod common;

use std::time::Duration;

/// Tests that non-participant MPC nodes automatically submit their TEE
/// attestations to the contract after startup.
///
/// Setup: 4 nodes started, but only 2 are initial participants. The other 2
/// should submit attestations on their own. We verify all 4 appear in the
/// contract's TEE accounts list.
#[tokio::test]
async fn test_submit_participant_info() {
    let (cluster, _running) =
        common::setup_cluster(common::SUBMIT_PARTICIPANT_INFO_PORT_SEED, |c| {
            c.num_nodes = 4;
            c.initial_participants = 2;
        })
        .await;

    // Poll until all 4 nodes have TEE attestations in the contract.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let tee_accounts = cluster
            .get_tee_accounts()
            .await
            .expect("failed to query TEE accounts");

        if tee_accounts.len() >= 4 {
            tracing::info!(
                count = tee_accounts.len(),
                "all nodes submitted attestations"
            );
            return;
        }

        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for all 4 nodes to submit attestations, only {} found",
            tee_accounts.len()
        );
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}
