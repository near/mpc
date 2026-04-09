mod common;

use std::time::Duration;

use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::{DomainPurpose, SignatureScheme};
use rand::SeedableRng;

/// Fetch a URL and assert the response body contains all of `expected`.
async fn assert_body_contains(client: &reqwest::Client, node: usize, url: &str, expected: &[&str]) {
    let resp = client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("node {node}: GET {url} failed: {e}"));
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "node {node}: {url}");
    let body = resp
        .text()
        .await
        .unwrap_or_else(|e| panic!("node {node}: reading body from {url} failed: {e}"));
    for s in expected {
        assert!(
            body.contains(s),
            "node {node}: {url} missing {s:?}\nbody: {body}"
        );
    }
}

#[tokio::test]
async fn test_web_endpoints() {
    let (cluster, running) = common::setup_cluster(common::WEB_ENDPOINTS_PORT_SEED, |_| {}).await;

    // Send one request per domain.
    assert!(!running.domains.domains.is_empty(), "no domains found");
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for domain in &running.domains.domains {
        let outcome = match domain.purpose {
            Some(DomainPurpose::Sign) => {
                let payload = match domain.scheme {
                    SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
                        common::generate_ecdsa_payload(&mut rng)
                    }
                    SignatureScheme::Ed25519 => common::generate_eddsa_payload(&mut rng),
                    _ => continue,
                };
                cluster
                    .send_sign_request(domain.id, payload)
                    .await
                    .expect("sign request transaction failed")
            }
            Some(DomainPurpose::CKD) => cluster
                .send_ckd_request(domain.id, common::generate_ckd_app_public_key())
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

        assert_body_contains(&client, i, &format!("http://{web_addr}/health"), &["OK"]).await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/metrics"),
            &["mpc_num_signature_requests_indexed"],
        )
        .await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/tasks"),
            &["root:"],
        )
        .await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/blocks"),
            &["Recent blocks:", "reqs:"],
        )
        .await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/signatures"),
            &["Recent signatures:", "id:"],
        )
        .await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/ckds"),
            &["Recent ckds:", "id:"],
        )
        .await;
        assert_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/contract"),
            &["Contract is in Running state"],
        )
        .await;

        // pprof flamegraph: verify SVG content-type and body.
        let resp = client
            .get(format!(
                "http://{pprof_addr}/profiler/pprof/flamegraph?sampling_duration_secs=1"
            ))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .unwrap_or_else(|e| panic!("node {i}: pprof request failed: {e}"));
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "node {i}: pprof status"
        );
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

        tracing::info!(node = i, "all web endpoints verified");
    }
}
