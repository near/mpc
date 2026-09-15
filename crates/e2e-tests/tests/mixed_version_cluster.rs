//! Runs a cluster where half the nodes are a previous release, to check that the current
//! binary keeps signing with them and never sends them a task id they cannot decode.
//!
//! Ignored by default because it needs a previous-release `mpc-node`: build one from a
//! checkout of the last release tag and point `MPC_NODE_OLD_BINARY` at it, then run
//! `cargo make e2e-tests-skip-build mixed_version_cluster --run-ignored all`.

use crate::common::{MIXED_VERSION_CLUSTER_PORT_SEED, generate_ecdsa_payload, must_setup_cluster};
use e2e_tests::metrics;
use near_mpc_contract_interface::types::Protocol;
use rand::{SeedableRng, rngs::StdRng};
use std::path::PathBuf;

const OLD_BINARY_ENV: &str = "MPC_NODE_OLD_BINARY";
/// Handshake protocol version advertised by binaries that predate online presigning.
const PREVIOUS_PROTOCOL_VERSION: i64 = 8;
const CURRENT_PROTOCOL_VERSION: i64 = 9;
const NUM_REQUESTS: usize = 6;

#[tokio::test]
#[ignore = "needs a previous-release mpc-node binary in MPC_NODE_OLD_BINARY"]
#[expect(non_snake_case)]
async fn mixed_version_cluster__should_sign_and_never_send_old_peers_new_task_ids() {
    // Given
    let old_binary =
        PathBuf::from(std::env::var(OLD_BINARY_ENV).unwrap_or_else(|_| {
            panic!("{OLD_BINARY_ENV} must point at a previous-release mpc-node")
        }));
    let (cluster, running) = must_setup_cluster(MIXED_VERSION_CLUSTER_PORT_SEED, |c| {
        c.num_nodes = 4;
        c.initial_participant_indices = (0..4).collect();
        c.threshold = 3;
        let current_binary = c.binary_paths[0].clone();
        c.binary_paths = vec![
            old_binary.clone(),
            old_binary.clone(),
            current_binary.clone(),
            current_binary,
        ];
    })
    .await;
    let ecdsa_domain = running
        .domains
        .domains
        .iter()
        .find(|domain| domain.protocol == Protocol::CaitSith)
        .expect("cluster should have a cait-sith domain")
        .clone();
    let mut rng = StdRng::seed_from_u64(0);

    // When
    for _ in 0..NUM_REQUESTS {
        let outcome = cluster
            .send_sign_request(
                ecdsa_domain.id,
                generate_ecdsa_payload(&mut rng),
                cluster.default_user_account(),
            )
            .await
            .expect("sign request transaction failed");
        assert!(outcome.is_success(), "{:?}", outcome.failure_message());
    }

    // Then
    for new_node in [2, 3] {
        let mut versions: Vec<i64> = cluster
            .get_labelled_metric(new_node, metrics::PEER_PROTOCOL_VERSION)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        versions.sort_unstable();
        assert_eq!(
            versions,
            vec![
                PREVIOUS_PROTOCOL_VERSION,
                PREVIOUS_PROTOCOL_VERSION,
                CURRENT_PROTOCOL_VERSION
            ],
            "node {new_node} should see two old peers and one current peer"
        );
        // With two current nodes out of four and t = 3, no triple pair is all-current, so a
        // current leader must have taken the presignature path every time.
        let online_presign: Vec<i64> = cluster
            .get_labelled_metric(new_node, metrics::ECDSA_SIGNATURES_LED_BY_MODE)
            .await
            .unwrap()
            .into_iter()
            .filter(|(labels, _)| labels.contains("online_presign"))
            .map(|(_, value)| value)
            .collect();
        assert!(
            online_presign.iter().all(|count| *count == 0),
            "node {new_node} led an online-presign signature with old peers"
        );
    }
}
