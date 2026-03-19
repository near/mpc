use e2e_tests::{ClusterConfig, E2ePortAllocator, MpcCluster};

/// Port of `pytest/tests/shared_cluster_tests/test_requests.py::test_request_lifecycle`.
///
/// Starts a 2-node MPC cluster, submits 10 signature requests per Sign domain
/// (Secp256k1, Ed25519) and 10 CKD requests per CKD domain (Bls12381), and
/// verifies that all succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_request_lifecycle() -> anyhow::Result<()> {
    let config = ClusterConfig {
        num_nodes: 2,
        threshold: 2,
        triples_to_buffer: 200,
        presignatures_to_buffer: 100,
        port_allocator: E2ePortAllocator::new(1),
        ..ClusterConfig::default()
    };

    let cluster = MpcCluster::start(config).await?;

    cluster.send_and_await_signature_requests(10).await?;
    cluster.send_and_await_ckd_requests(10).await?;

    Ok(())
}
