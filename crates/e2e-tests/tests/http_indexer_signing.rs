use crate::common::{
    HTTP_INDEXER_RECOVERY_PORT_SEED, HTTP_INDEXER_SIGNING_PORT_SEED, must_setup_cluster,
    wait_for_node_indexer_height_above, wait_for_presignatures,
};
use anyhow::{Context, ensure};
use e2e_tests::{
    CLUSTER_WAIT_TIMEOUT, MpcCluster, caller::WithWaitLevel, metrics, mpc_node::NodeIndexer,
};
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use near_kit::{ExecutedOptimistic, Included};
use near_mpc_contract_interface::types::{
    DomainId, Payload, PublicKey, SignRequestArgs, SignatureResponse,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn must_sample_count(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .expect("sample count must be a non-negative integer"),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("{name}: {error}"),
    }
}

fn must_save_report(path: &Path, report: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(report).unwrap()).unwrap();
}

async fn sign_and_verify(
    cluster: &MpcCluster,
    client: &near_kit::Near,
    domain: DomainId,
    verifying_key: &VerifyingKey,
    index: usize,
    warmup: bool,
    after_restart: bool,
) -> Value {
    let mut payload = [0u8; 32];
    payload[24..].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
    let mut sample = json!({"index": index, "payload": payload, "warmup": warmup, "after_restart": after_restart});
    let sent = Instant::now();
    let outcome = match cluster
        .send_sign_request(
            domain,
            Payload::Ecdsa(payload.into()),
            cluster.default_user_account(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            sample["elapsed_ms"] = json!(sent.elapsed().as_millis());
            sample["error"] = json!(format!("submission: {error:#}"));
            return sample;
        }
    };
    let verification = (|| -> anyhow::Result<SignatureResponse> {
        ensure!(outcome.is_success(), "{:?}", outcome.failure_message());
        let response: SignatureResponse = outcome.json()?;
        let SignatureResponse::Secp256k1(signature) = &response else {
            anyhow::bail!("expected secp256k1 signature");
        };
        let signature = Signature::try_from(signature)?;
        verifying_key.verify_prehash(&payload, &signature)?;
        let mut wrong_payload = payload;
        wrong_payload[0] ^= 1;
        ensure!(
            verifying_key
                .verify_prehash(&wrong_payload, &signature)
                .is_err(),
            "wrong payload verified"
        );
        Ok(response)
    })();
    sample["elapsed_ms"] = json!(sent.elapsed().as_millis());
    match verification {
        Ok(response) => {
            sample["signature"] = json!(response);
            sample["verified"] = json!(true);
        }
        Err(error) => sample["error"] = json!(format!("verification: {error:#}")),
    }
    match client
        .rpc()
        .call::<_, Value>(
            "tx",
            json!({
                "tx_hash": outcome.transaction_hash(),
                "sender_account_id": cluster.default_user_account(),
                "wait_until": "EXECUTED_OPTIMISTIC"
            }),
        )
        .await
    {
        Ok(raw) => sample["outcome"] = raw,
        Err(error) => sample["outcome_error"] = json!(error.to_string()),
    }
    sample
}

async fn restart_nodes(cluster: &mut MpcCluster) -> anyhow::Result<()> {
    let indices = [0, 1, 2];
    let heights = cluster
        .get_metric_all_nodes(metrics::INDEXER_LATEST_BLOCK_HEIGHT)
        .await?;
    for index in indices {
        let status = cluster.terminate_node_with_sigterm(index, Duration::from_secs(30))?;
        ensure!(
            status.success(),
            "node {index} did not shut down cleanly: {status}"
        );
        let home = cluster.test_dir.path().join(format!("node{index}"));
        for stream in ["stdout", "stderr"] {
            std::fs::copy(
                home.join(format!("{stream}.log")),
                home.join(format!("{stream}.before-restart.log")),
            )?;
        }
    }
    cluster.start_nodes(&indices)?;
    for index in indices {
        cluster.wait_for_node_healthy(index).await?;
        wait_for_node_indexer_height_above(
            cluster,
            index,
            heights[index].context("missing pre-restart height")?,
            CLUSTER_WAIT_TIMEOUT,
        )
        .await?;
    }
    wait_for_presignatures(cluster, &indices, 2).await
}

#[tokio::test]
#[ignore = "requires MPC_E2E_BINARY, custom NEAR_SANDBOX_BIN_PATH, and both contract WASMs"]
#[expect(non_snake_case)]
async fn local_indexer__should_complete_and_verify_real_threshold_signatures() {
    // Given
    let binary = PathBuf::from(std::env::var_os("MPC_E2E_BINARY").expect("MPC_E2E_BINARY"));
    let mode = std::env::var("MPC_E2E_INDEXER").unwrap_or_else(|_| "embedded".into());
    let measured = must_sample_count("MPC_E2E_SAMPLES", 2);
    let warmup = must_sample_count("MPC_E2E_WARMUP", 0);
    let restart = must_sample_count("MPC_E2E_RESTART", 0);
    assert!(measured > 0 && restart <= 1);
    assert!(
        restart == 0 || (measured == 2 && warmup == 0),
        "restart mode requires 2 samples and no warmup"
    );
    let indexer = match mode.as_str() {
        "embedded" => NodeIndexer::EmbeddedOptimisticLatest,
        "http" => NodeIndexer::Http { rpc_url: None },
        _ => panic!("MPC_E2E_INDEXER must be embedded or http"),
    };
    let started = Instant::now();
    let (mut cluster, running) = must_setup_cluster(HTTP_INDEXER_SIGNING_PORT_SEED, |config| {
        config.binary_paths = vec![binary];
        config.node_indexer = indexer;
        config.sandbox_indexer_comparison = true;
        config.domains.truncate(1);
        config.triples_to_buffer = 6;
        config.presignatures_to_buffer = 2;
    })
    .await;
    cluster.test_dir.keep();
    let ready_ms = started.elapsed().as_millis();
    let domain = &running.domains.domains[0];
    let client = near_kit::Near::custom(cluster.sandbox.rpc_url(), "sandbox").build();
    let public_key: PublicKey = client.view(cluster.contract_id(), "derived_public_key")
        .args(json!({"path": "test", "predecessor": cluster.default_user_account(), "domain_id": domain.id}))
        .await.unwrap();
    let PublicKey::Secp256k1(public_key) = public_key else {
        panic!("expected secp256k1 domain");
    };
    let verifying_key = VerifyingKey::from(k256::PublicKey::try_from(&public_key).unwrap());
    let mut report = json!({"mode": mode, "finality": "optimistic", "sync_mode": "Latest", "ready_ms": ready_ms, "public_key": public_key, "requested_samples": measured, "warmup_samples": warmup, "restart": restart == 1, "samples": [], "complete": false});
    let report_path = cluster.test_dir.path().join("verified-signatures.json");
    report["status_start"] = client
        .rpc()
        .call::<_, Value>("status", json!({}))
        .await
        .unwrap();
    must_save_report(&report_path, &report);
    assert_eq!(
        report["status_start"]["protocol_version"],
        json!(86),
        "unexpected starting protocol"
    );

    // When
    for index in 0..(warmup + measured + restart * 2) {
        if restart == 1 && index == 2 {
            let started = Instant::now();
            let result = restart_nodes(&mut cluster).await;
            report["restart_ms"] = json!(started.elapsed().as_millis());
            if let Err(error) = &result {
                report["restart_error"] = json!(format!("{error:#}"));
            }
            must_save_report(&report_path, &report);
            result.expect("restart failed; evidence retained");
        }
        let sample = sign_and_verify(
            &cluster,
            &client,
            domain.id,
            &verifying_key,
            index,
            index < warmup,
            restart == 1 && index >= 2,
        )
        .await;

        // Then
        let passed = sample["error"].is_null() && sample["outcome_error"].is_null();
        report["samples"].as_array_mut().unwrap().push(sample);
        must_save_report(&report_path, &report);
        assert!(
            passed,
            "sample failed; evidence retained at {}",
            report_path.display()
        );
    }
    match client.rpc().call::<_, Value>("status", json!({})).await {
        Ok(status) => report["status_end"] = status,
        Err(error) => report["status_end_error"] = json!(error.to_string()),
    }
    let protocol_unchanged = report["status_end"]["protocol_version"] == json!(86);
    report["complete"] = json!(protocol_unchanged);
    must_save_report(&report_path, &report);
    assert!(
        protocol_unchanged,
        "ending protocol/status check failed; evidence retained"
    );
    tracing::info!(artifacts = %cluster.test_dir.path().display(), "verified real threshold signatures");
}

#[tokio::test]
#[ignore = "requires MPC_E2E_BINARY, custom NEAR_SANDBOX_BIN_PATH, and both contract WASMs"]
#[expect(non_snake_case)]
async fn http_indexer__should_recover_pending_request_after_process_interruption() {
    // Given
    let binary = PathBuf::from(std::env::var_os("MPC_E2E_BINARY").expect("MPC_E2E_BINARY"));
    let (mut cluster, running) = must_setup_cluster(HTTP_INDEXER_RECOVERY_PORT_SEED, |config| {
        config.binary_paths = vec![binary];
        config.node_indexer = NodeIndexer::Http { rpc_url: None };
        config.sandbox_indexer_comparison = true;
        config.domains.truncate(1);
        config.triples_to_buffer = 6;
        config.presignatures_to_buffer = 2;
    })
    .await;
    cluster.test_dir.keep();
    let domain = running.domains.domains[0].id;
    let client = near_kit::Near::custom(cluster.sandbox.rpc_url(), "sandbox").build();
    let public_key: PublicKey = client.view(cluster.contract_id(), "derived_public_key")
        .args(json!({"path": "test", "predecessor": cluster.default_user_account(), "domain_id": domain}))
        .await.unwrap();
    let PublicKey::Secp256k1(public_key) = public_key else {
        panic!("expected secp256k1 domain")
    };
    let verifying_key = VerifyingKey::from(k256::PublicKey::try_from(&public_key).unwrap());
    let report_path = cluster
        .test_dir
        .path()
        .join("pending-request-recovery.json");
    let mut report = json!({"complete": false, "mode": "http", "restart_sync_mode": "Interruption", "public_key": public_key, "checkpoints_before": []});
    must_save_report(&report_path, &report);
    let result: anyhow::Result<()> = async {
        tokio::time::timeout(CLUSTER_WAIT_TIMEOUT, async {
            loop {
                if [0, 1, 2].iter().all(|index| {
                    cluster.test_dir.path().join(format!("node{index}/http-indexer-checkpoint.json")).is_file()
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await?;
        for index in [0, 1, 2] {
            let status = cluster.terminate_node_with_sigterm(index, Duration::from_secs(30))?;
            ensure!(status.success(), "node {index} did not stop cleanly");
            let home = cluster.test_dir.path().join(format!("node{index}"));
            let checkpoint: Value = serde_json::from_slice(&std::fs::read(home.join("http-indexer-checkpoint.json"))?)?;
            report["checkpoints_before"].as_array_mut().unwrap().push(checkpoint);
            for stream in ["stdout", "stderr"] {
                std::fs::copy(home.join(format!("{stream}.log")), home.join(format!("{stream}.before-restart.log")))?;
            }
            let path = home.join("start_config.toml");
            let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
            config["node"]["indexer"]["sync_mode"] = toml::Value::String("Interruption".into());
            std::fs::write(path, toml::to_string(&config)?)?;
        }
        report["status_offline"] = client.rpc().call::<_, Value>("status", json!({})).await?;
        ensure!(report["status_offline"]["protocol_version"] == json!(86), "unexpected protocol");
        must_save_report(&report_path, &report);

        // When: the sign receipt executes while every MPC process is offline.
        let payload = [7u8; 32];
        let submitted = cluster.contract_handle(cluster.default_user_account())
            .with_wait_level::<Included>()
            .sign(SignRequestArgs::new("test".into(), Payload::Ecdsa(payload.into()), domain))
            .await?;
        report["transaction_hash"] = json!(submitted.transaction_hash);
        let pending = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let raw: Value = client.rpc().call("tx", json!({"tx_hash": submitted.transaction_hash, "sender_account_id": submitted.sender_id, "wait_until": "NONE"})).await?;
                let executed_sign = raw["receipts_outcome"].as_array().is_some_and(|receipts| receipts.iter().any(|receipt| {
                    receipt["outcome"]["executor_id"] == json!(cluster.contract_id())
                        && receipt["outcome"]["logs"].as_array().is_some_and(|logs| logs.iter().any(|log| log.as_str().is_some_and(|log| log.starts_with("sign: predecessor="))))
                        && receipt["outcome"]["status"]["SuccessReceiptId"].is_string()
                }));
                if executed_sign {
                    ensure!(raw["status"] == json!("Started"), "offline request already completed: {}", raw["status"]);
                    break Ok::<Value, anyhow::Error>(raw);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        report["pending_outcome"] = pending;
        must_save_report(&report_path, &report);
        cluster.start_nodes(&[0, 1, 2])?;
        let outcome = tokio::time::timeout(CLUSTER_WAIT_TIMEOUT, client.tx_status(&submitted.transaction_hash, &submitted.sender_id).wait_until::<ExecutedOptimistic>()).await??;

        // Then: replay from retained checkpoints reconstructs enough state to sign.
        ensure!(outcome.is_success(), "{:?}", outcome.failure_message());
        let response: SignatureResponse = outcome.json()?;
        let SignatureResponse::Secp256k1(signature) = &response else { anyhow::bail!("expected secp256k1 signature") };
        let signature = Signature::try_from(signature)?;
        verifying_key.verify_prehash(&payload, &signature)?;
        let mut wrong_payload = payload;
        wrong_payload[0] ^= 1;
        ensure!(verifying_key.verify_prehash(&wrong_payload, &signature).is_err(), "wrong payload verified");
        report["signature"] = json!(response);
        report["verified"] = json!(true);
        report["outcome"] = client.rpc().call::<_, Value>("tx", json!({"tx_hash": submitted.transaction_hash, "sender_account_id": submitted.sender_id, "wait_until": "EXECUTED_OPTIMISTIC"})).await?;
        report["status_end"] = client.rpc().call::<_, Value>("status", json!({})).await?;
        ensure!(report["status_end"]["protocol_version"] == json!(86), "unexpected ending protocol");
        report["complete"] = json!(true);
        Ok(())
    }.await;
    if let Err(error) = &result {
        report["error"] = json!(format!("{error:#}"));
    }
    must_save_report(&report_path, &report);
    result.expect("pending-request recovery failed; evidence retained");
}
