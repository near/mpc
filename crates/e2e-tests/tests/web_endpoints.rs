use crate::common;

use std::time::Duration;

use anyhow::Context;
use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::DomainPurpose;
use rand::SeedableRng;

async fn fetch_body(client: &reqwest::Client, node: usize, url: &str) -> anyhow::Result<String> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("node {node}: GET {url} failed"))?
        .error_for_status()
        .with_context(|| format!("node {node}: {url} returned non-success"))?
        .text()
        .await
        .with_context(|| format!("node {node}: reading body from {url} failed"))
}

/// Fetch a URL and ensure the response body contains all of `expected`.
async fn ensure_body_contains(
    client: &reqwest::Client,
    node: usize,
    url: &str,
    expected: &[&str],
) -> anyhow::Result<()> {
    let body = fetch_body(client, node, url).await?;
    for s in expected {
        anyhow::ensure!(
            body.contains(s),
            "node {node}: {url} missing {s:?}\nbody: {body}"
        );
    }
    Ok(())
}

/// Polls the URL until a successful response body satisfies the predicate, or
/// fails once the timeout elapses.
async fn wait_for_body(
    client: &reqwest::Client,
    node: usize,
    url: &str,
    timeout: Duration,
    done: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let body = fetch_body(client, node, url).await?;
        if done(&body) {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "node {node}: {url} body did not match within {timeout:?}\nlast body:\n{body}"
        );
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// Regex matching one rendered recent-transactions row for a node's keygen
/// `vote_pk` submission. Stable tokens (status, method, signer, key) are matched
/// exactly; run-specific ones (timestamp, txid, nonce, block, sig) are matched by
/// pattern only.
fn vote_pk_row_regex(signer_account_id: &str, signer_key: &str) -> regex::Regex {
    let base58 = r"[1-9A-HJ-NP-Za-km-z]+";
    let int = r"\d+";
    let date = r"\d{4}-\d{2}-\d{2}";
    // `time::OffsetDateTime` renders the hour unpadded (e.g. "7:44:16"), so the
    // hour is 1-2 digits while minute and second are always zero-padded.
    let time = r"\d{1,2}:\d{2}:\d{2}\.\d+";
    let offset = r"\+00:00:00";

    // `submitted_at`, e.g. "2026-06-10 09:22:59.0 +00:00:00".
    let timestamp = format!("{date} {time} {offset}");
    let status = "Unknown +";
    let method = "method=vote_pk +";

    let signer = regex::escape(signer_account_id);
    let key = regex::escape(signer_key);
    let signer_key = format!("signer={signer} key={key}");

    let txid = format!("txid={base58}");
    let nonce = format!("nonce={int}");
    let block = format!("block={int}");
    let sig = format!("sig=ed25519:{base58}");
    let metadata = format!("{txid}  {nonce}  {block}  {sig}");

    regex::Regex::new(&format!(
        "^  {timestamp}  {status}{method}{signer_key}  {metadata}$"
    ))
    .expect("valid regex")
}

#[tokio::test]
async fn test_web_endpoints() {
    let (cluster, running) =
        common::must_setup_cluster(common::WEB_ENDPOINTS_PORT_SEED, |_| {}).await;

    // Send one request per domain.
    assert!(!running.domains.domains.is_empty(), "no domains found");
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for domain in &running.domains.domains {
        let outcome = match domain.purpose {
            DomainPurpose::Sign => {
                let payload = common::must_get_payload_for_domain(domain, &mut rng);
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

        ensure_body_contains(&client, i, &format!("http://{web_addr}/health"), &["OK"])
            .await
            .expect("health endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/metrics"),
            &[
                "mpc_num_signature_requests_indexed", // representative of mpc metrics
                "near_block_processed_total",         // representative of nearcore metrics
            ],
        )
        .await
        .expect("metrics endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/tasks"),
            &["root:"],
        )
        .await
        .expect("debug/tasks endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/blocks"),
            &["Recent blocks:"],
        )
        .await
        .expect("debug/blocks endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/signatures"),
            &["Recent signatures:", "id:"],
        )
        .await
        .expect("debug/signatures endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/ckds"),
            &["Recent ckds:", "id:"],
        )
        .await
        .expect("debug/ckds endpoint failed");
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/contract"),
            &["Contract is in Running state"],
        )
        .await
        .expect("debug/contract endpoint failed");

        // The nearcore config endpoint exposes the effective on-disk config.json;
        // `genesis_file` is always present in a loaded config.
        ensure_body_contains(
            &client,
            i,
            &format!("http://{web_addr}/debug/nearcore_config"),
            &["genesis_file"],
        )
        .await
        .expect("debug/nearcore_config endpoint failed");

        // Check the recent-transactions page lists this node's transactions.
        // During keygen every node submits one `vote_pk` transaction per domain,
        // so the page should show the header plus exactly one matching row per
        // domain. We poll because a row only appears after the node observes the
        // transaction's outcome, which takes a few seconds.
        let row = vote_pk_row_regex(
            node.setup().account_id().as_ref(),
            &String::from(&node.setup().near_signer_public_key()),
        );
        let expected_vote_pk_rows = running.domains.domains.len();
        wait_for_body(
            &client,
            i,
            &format!("http://{web_addr}/debug/recent_transactions"),
            Duration::from_secs(15),
            |body| {
                const HEADER: &str =
                    "Recently submitted transactions (newest first, up to 2000 retained):";
                let mut lines = body.lines();
                lines.next() == Some(HEADER)
                    && lines.filter(|line| row.is_match(line)).count() == expected_vote_pk_rows
            },
        )
        .await
        .expect("debug/recent_transactions never rendered a vote_pk row per keygen domain");

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
