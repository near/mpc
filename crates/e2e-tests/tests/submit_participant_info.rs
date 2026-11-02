use crate::common;

use e2e_tests::PARTICIPANT_ATTESTATIONS_TIMEOUT;
use e2e_tests::caller::VIEW_POLL_INTERVAL;
use near_contract_transport::watch::{Subscribe, wait_for};

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

    let mpc_contract = cluster.mpc_contract.clone();
    let mut tee_accounts = mpc_contract
        .get_tee_accounts()
        .subscribe(VIEW_POLL_INTERVAL)
        .await;
    wait_for(
        &mut tee_accounts,
        PARTICIPANT_ATTESTATIONS_TIMEOUT,
        |tee_accounts| tee_accounts.len() == 4,
    )
    .await
    .expect("timed out waiting for all 4 nodes to submit attestations");
}
