use std::assert_matches;
use std::time::Duration;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::mpc_node::HTTP_INDEXER_CHECKPOINT_FILE;
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, IndexerBackend, MpcCluster, metrics};
use near_mpc_contract_interface::types::{
    RunningContractState, SignRequestArgs, SignatureRequest, SignatureResponse,
};
use rand::{SeedableRng, rngs::StdRng};

use crate::common::{
    HTTP_INDEXER_OFFLINE_REQUEST_PORT_SEED, HTTP_INDEXER_RESTART_PORT_SEED, POLL_INTERVAL,
    generate_ecdsa_payload, must_setup_cluster, send_sign_request,
    wait_for_node_indexer_height_above,
};

const NODES: [usize; 3] = [0, 1, 2];
const SIGTERM_GRACE: Duration = Duration::from_secs(30);
/// The sign receipt yields within a few blocks of submission. Waiting longer
/// would eat into the contract's yield timeout, which the restarted nodes need.
const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A cluster with a single Secp256k1 signing domain.
async fn must_setup_http_cluster(port_seed: u16) -> (MpcCluster, RunningContractState) {
    must_setup_cluster(port_seed, |config| {
        config.indexer = IndexerBackend::Http;
        config.domains.truncate(1);
    })
    .await
}

fn must_stop_all_nodes(cluster: &mut MpcCluster) {
    for index in NODES {
        let status = cluster
            .terminate_node_with_sigterm(index, SIGTERM_GRACE)
            .expect("node did not stop within the SIGTERM grace period");
        assert!(
            status.success(),
            "node {index} did not stop cleanly: {status}"
        );
    }
}

async fn must_wait_for_checkpoints(cluster: &MpcCluster) {
    let checkpoints: Vec<_> = NODES
        .iter()
        .map(|index| {
            cluster
                .test_dir
                .path()
                .join(format!("node{index}"))
                .join(HTTP_INDEXER_CHECKPOINT_FILE)
        })
        .collect();
    let max_times =
        usize::try_from(CLUSTER_WAIT_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis()).unwrap();
    (|| async {
        anyhow::ensure!(
            checkpoints.iter().all(|path| path.is_file()),
            "not every node has persisted a checkpoint"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
    .expect("HTTP indexers did not persist checkpoints");
}

#[tokio::test]
#[expect(non_snake_case)]
async fn http_indexer__should_keep_signing_after_every_node_restarts() {
    // Given
    let (mut cluster, running) = must_setup_http_cluster(HTTP_INDEXER_RESTART_PORT_SEED).await;
    let mut rng = StdRng::seed_from_u64(0);
    let user = cluster.default_user_account().clone();
    send_sign_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("sign request before the restart failed");
    let heights = cluster
        .get_metric_all_nodes(metrics::INDEXER_LATEST_BLOCK_HEIGHT)
        .await
        .expect("failed to read indexer heights");

    // When
    must_stop_all_nodes(&mut cluster);
    cluster
        .start_nodes(&NODES)
        .expect("failed to restart nodes");
    for index in NODES {
        cluster
            .wait_for_node_healthy(index)
            .await
            .expect("restarted node is not healthy");
        let height = heights[index].expect("missing indexer height before the restart");
        wait_for_node_indexer_height_above(&cluster, index, height, CLUSTER_WAIT_TIMEOUT)
            .await
            .expect("restarted indexer did not advance");
    }

    // Then
    send_sign_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("sign request after the restart failed");
}

#[tokio::test]
#[expect(non_snake_case)]
async fn http_indexer__should_respond_to_a_request_submitted_while_every_node_was_stopped() {
    // Given
    let (mut cluster, running) =
        must_setup_http_cluster(HTTP_INDEXER_OFFLINE_REQUEST_PORT_SEED).await;
    let domain = running.domains.domains[0].id;
    must_wait_for_checkpoints(&cluster).await;
    must_stop_all_nodes(&mut cluster);
    let user = cluster.default_user_account().clone();
    let payload = generate_ecdsa_payload(&mut StdRng::seed_from_u64(1));
    let sign = {
        let handle = cluster.contract_handle(&user);
        let args = SignRequestArgs::new("test".to_string(), payload.clone(), domain);
        tokio::spawn(async move { handle.sign(args).await })
    };
    let request = SignatureRequest::new(domain, payload, &user, "test");
    let max_times =
        usize::try_from(PENDING_REQUEST_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis()).unwrap();
    (|| async {
        let pending = cluster
            .mpc_contract_handle
            .get_pending_request(request.clone())
            .await?
            .value;
        anyhow::ensure!(pending.is_some(), "the sign request is not pending yet");
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
    .expect("the sign request did not become pending");

    // When
    cluster
        .start_nodes(&NODES)
        .expect("failed to restart nodes");
    let outcome = tokio::time::timeout(CLUSTER_WAIT_TIMEOUT, sign)
        .await
        .expect("no response to the pending sign request")
        .unwrap()
        .expect("failed to submit the sign request");

    // Then
    assert!(
        outcome.is_success(),
        "pending sign request failed: {:?}",
        outcome.failure_message()
    );
    let response: SignatureResponse = outcome.json().unwrap();
    assert_matches!(response, SignatureResponse::Secp256k1(_));
}
