mod common;

use std::time::Duration;

use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::{DomainPurpose, SignatureScheme};

#[tokio::test]
async fn test_web_endpoints() {
    let (cluster, running) = common::setup_cluster(common::WEB_ENDPOINTS_PORT_SEED, |_| {}).await;

    // Send one sign request.
    let sign_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.scheme == SignatureScheme::Secp256k1 && d.purpose == Some(DomainPurpose::Sign))
        .expect("no Secp256k1 Sign domain found");

    let outcome = cluster
        .send_sign_request(sign_domain.id, common::generate_ecdsa_payload())
        .await
        .expect("sign request transaction failed");
    assert!(
        outcome.is_success(),
        "sign request failed: {:?}",
        outcome.failure_message()
    );

    // Send one CKD request.
    let ckd_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == Some(DomainPurpose::CKD))
        .expect("no CKD domain found");

    let outcome = cluster
        .send_ckd_request(ckd_domain.id, common::generate_ckd_app_public_key())
        .await
        .expect("ckd request transaction failed");
    assert!(
        outcome.is_success(),
        "ckd request failed: {:?}",
        outcome.failure_message()
    );

    // Verify web endpoints on each node.
    let client = reqwest::Client::new();
    for (i, node_state) in cluster.nodes.iter().enumerate() {
        let node = match node_state {
            MpcNodeState::Running(n) => n,
            _ => panic!("node {i} is not running"),
        };
        let web_addr = node.web_address();
        let pprof_addr = node.pprof_address();

        // GET /health
        let resp = client
            .get(format!("http://{web_addr}/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "node {i}: /health status");
        let body = resp.text().await.unwrap();
        assert!(body.contains("OK"), "node {i}: /health body: {body}");

        // GET /metrics
        let resp = client
            .get(format!("http://{web_addr}/metrics"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("mpc_num_signature_requests_indexed"),
            "node {i}: /metrics missing expected metric"
        );

        // GET /debug/tasks
        let resp = client
            .get(format!("http://{web_addr}/debug/tasks"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("root:"),
            "node {i}: /debug/tasks body: {body}"
        );

        // GET /debug/blocks
        let resp = client
            .get(format!("http://{web_addr}/debug/blocks"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("Recent blocks:"),
            "node {i}: /debug/blocks body: {body}"
        );
        assert!(
            body.contains("reqs:"),
            "node {i}: /debug/blocks missing 'reqs:': {body}"
        );

        // GET /debug/signatures
        let resp = client
            .get(format!("http://{web_addr}/debug/signatures"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("Recent signatures:"),
            "node {i}: /debug/signatures body: {body}"
        );
        assert!(
            body.contains("id:"),
            "node {i}: /debug/signatures missing 'id:': {body}"
        );

        // GET /debug/ckds
        let resp = client
            .get(format!("http://{web_addr}/debug/ckds"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("Recent ckds:"),
            "node {i}: /debug/ckds body: {body}"
        );
        assert!(
            body.contains("id:"),
            "node {i}: /debug/ckds missing 'id:': {body}"
        );

        // GET /debug/contract
        let resp = client
            .get(format!("http://{web_addr}/debug/contract"))
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("Contract is in Running state"),
            "node {i}: /debug/contract body: {body}"
        );

        // GET /profiler/pprof/flamegraph
        let resp = client
            .get(format!(
                "http://{pprof_addr}/profiler/pprof/flamegraph?sampling_duration_secs=1"
            ))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "node {i}: pprof status");
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
        assert!(body.contains("<svg"), "node {i}: flamegraph missing <svg");
        assert!(
            body.contains("</svg>"),
            "node {i}: flamegraph missing </svg>"
        );

        tracing::info!(node = i, "all web endpoints verified");
    }
}
