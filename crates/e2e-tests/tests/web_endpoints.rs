use crate::common;

use std::time::Duration;

use anyhow::Context;
use e2e_tests::MpcNodeState;
use mpc_primitives::domain::Curve;
use near_mpc_contract_interface::types::DomainPurpose;
use rand::SeedableRng;

/// Fetch a URL and assert the response body contains all of `expected`.
async fn assert_body_contains(
    client: &reqwest::Client,
    node: usize,
    url: &str,
    expected: &[&str],
) -> anyhow::Result<()> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("node {node}: GET {url} failed"))?;
    let status = resp.status();
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "node {node}: {url} unexpected status {status}"
    );
    let body = resp
        .text()
        .await
        .with_context(|| format!("node {node}: reading body from {url} failed"))?;
    for s in expected {
        anyhow::ensure!(
            body.contains(s),
            "node {node}: {url} missing {s:?}\nbody: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_web_endpoints() {
    let (cluster, running) = common::setup_cluster(common::WEB_ENDPOINTS_PORT_SEED, |_| {})
        .await
        .expect("setup_cluster failed");

    // Send one request per domain.
    assert!(!running.domains.domains.is_empty(), "no domains found");
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for domain in &running.domains.domains {
        let outcome = match domain.purpose {
            DomainPurpose::Sign => {
                let payload = match domain.curve {
                    Curve::Secp256k1 | Curve::V2Secp256k1 => {
                        common::generate_ecdsa_payload(&mut rng)
                    }
                    Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
                    _ => continue,
                };
                cluster
                    .send_sign_request(domain.id, payload, cluster.default_user_account())
                    .await
                    .expect("sign request transaction failed")
            }
            DomainPurpose::CKD => cluster
                .send_ckd_request(
                    domain.id,
                    common::generate_ckd_app_public_key(&mut rng),
                    cluster.default_user_account(),
                )
                .await
                .expect("ckd request transaction failed"),
            _ => continue,
        };
        assert!(
            outcome.is_success(),
            "request for domain {:?} failed: {:?}",
            domain.id,
            outcome.failure_message()
        );
    }

    // Verify web endpoints on each node.
    let client = reqwest::Client::new();
    for (i, node_state) in cluster.nodes.iter().enumerate() {
        let node = match node_state {
            MpcNodeState::Running(n) => n,
            _ => panic!("node {i} is not running"),
        };
        let web_addr = node.web_address();
        let pprof_addr = node.pprof_address();

        assert_body_contains(&client, i, &format!("http://{web_addr}/health"), &["OK"])
            .await
            .expect("health endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/metrics"),
            &["mpc_num_signature_requests_indexed"],
        )
        .await
        .expect("metrics endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/tasks"),
            &["root:"],
        )
        .await
        .expect("debug/tasks endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/blocks"),
            &["Recent blocks:", "reqs:"],
        )
        .await
        .expect("debug/blocks endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/signatures"),
            &["Recent signatures:", "id:"],
        )
        .await
        .expect("debug/signatures endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/ckds"),
            &["Recent ckds:", "id:"],
        )
        .await
        .expect("debug/ckds endpoint failed");
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/contract"),
            &["RunningContractState"],
        )
        .await
        .expect("debug/contract endpoint failed");

        // pprof flamegraph: verify the endpoint is reachable and returns either a
        // valid SVG (200) or no-content (204 — zero CPU samples captured because all
        // threads were sleeping in blocked libraries such as libc/pthread).
        let resp = client
            .get(format!(
                "http://{pprof_addr}/profiler/pprof/flamegraph?sampling_duration_secs=1"
            ))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .unwrap_or_else(|e| panic!("node {i}: pprof request failed: {e}"));
        let status = resp.status();
        assert!(
            status == reqwest::StatusCode::OK || status == reqwest::StatusCode::NO_CONTENT,
            "node {i}: unexpected pprof status {status}"
        );
        if status == reqwest::StatusCode::OK {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                content_type.starts_with("image/svg+xml"),
                "node {i}: wrong pprof content-type: {content_type}"
            );
            let body = resp.text().await.unwrap();
            assert!(
                body.contains("<svg") && body.contains("</svg>"),
                "node {i}: flamegraph missing svg tags"
            );
        }

        tracing::info!(node = i, "all web endpoints verified");
    }
}
