use crate::common;

use std::time::Duration;

use anyhow::Context;
use e2e_tests::MpcNodeState;
use mpc_primitives::domain::Protocol;
use near_mpc_contract_interface::types::DomainPurpose;
use rand::SeedableRng;

/// GETs `url` and returns the response body, erroring on a transport failure or
/// a non-success status.
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

/// Polls `url` until a 200 response body satisfies `done`, or fails after
/// `timeout`. Used for endpoints that populate asynchronously (e.g. the
/// recent-transactions page, which only records a row after the node observes
/// the transaction's outcome).
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
            "node {node}: {url} body did not match within {timeout:?}"
        );
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// Anchored regex matching one rendered `/debug/recent_transactions` row for a
/// node's keygen `vote_pk` submission. We key on `vote_pk` because every node
/// submits it during keygen, so the test can assert per-node, unlike `respond`
/// (leader-only); and because those rows land early in keygen, the poll catches
/// them on the first attempt. Deterministic tokens (status, method, signer
/// account, signer key) are matched exactly; run-dependent values (timestamp,
/// txid, nonce, block, sig) only by shape.
fn vote_pk_row_regex(signer_account_id: &str, signer_key: &str) -> regex::Regex {
    // Shared value shapes. The txid (a `CryptoHash`) and the keys/signatures all
    // render as base58.
    let base58 = r"[1-9A-HJ-NP-Za-km-z]+";
    let int = r"\d+";

    // `submitted_at`, e.g. "2026-06-10 09:22:59.0 +00:00:00".
    let date = r"\d{4}-\d{2}-\d{2}";
    let time = r"\d{2}:\d{2}:\d{2}\.\d+";
    let offset = r"\+00:00:00";
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

/// True if `body` is a `/debug/recent_transactions` page whose first line is the
/// header and which lists at least `expected_rows` rows matching `row` (a node's
/// per-domain keygen `vote_pk` rows)
fn lists_vote_pk_row_per_domain(body: &str, row: &regex::Regex, expected_rows: usize) -> bool {
    const HEADER: &str = "Recently submitted transactions (newest first, up to 2000 retained):";
    let mut lines = body.lines();
    lines.next() == Some(HEADER) && lines.filter(|line| row.is_match(line)).count() >= expected_rows
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
                let payload = match domain.protocol {
                    Protocol::CaitSith | Protocol::DamgardEtAl => {
                        common::generate_ecdsa_payload(&mut rng)
                    }
                    Protocol::Frost => common::generate_eddsa_payload(&mut rng),
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

        // A record is emitted only after the node observes the transaction's
        // outcome (`ensure_send_transaction` waits `TRANSACTION_TIMEOUT` first),
        // so poll rather than check once. Expect the header plus one `vote_pk`
        // row per keygen domain (every node votes once per domain; see
        // `vote_pk_row_regex`).
        let row = vote_pk_row_regex(
            node.setup().account_id().as_ref(),
            &node.setup().near_signer_public_key_str(),
        );
        let expected_vote_pk_rows = running.domains.domains.len();
        wait_for_body(
            &client,
            i,
            &format!("http://{web_addr}/debug/recent_transactions"),
            Duration::from_secs(15),
            |body| lists_vote_pk_row_per_domain(body, &row, expected_vote_pk_rows),
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
