pub mod common;
use common::{candidates, create_response, init, init_env, sign_and_validate};

use mpc_contract::errors;
use mpc_contract::primitives::{CandidateInfo, SignRequest};
use near_workspaces::types::AccountId;

use std::collections::HashMap;

#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let (_, contract, _, sk) = init_env().await;
    let predecessor_id = contract.id();
    let path = "test";

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    for msg in messages {
        println!("submitting: {msg}");
        let (payload_hash, respond_req, respond_resp) =
            create_response(predecessor_id, msg, path, &sk).await;
        let request = SignRequest {
            payload: payload_hash,
            path: path.into(),
            key_version: 0,
        };

        sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;
    }

    // check duplicate requests can also be signed:
    let duplicate_msg = "welp";
    let (payload_hash, respond_req, respond_resp) =
        create_response(predecessor_id, duplicate_msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };
    sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;
    sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;

    // Check that a sign with no response from MPC network properly errors out:
    let err = sign_and_validate(&request, None, &contract)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::MpcContractError::SignError(errors::SignError::Timeout).to_string()));

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_deposits() -> anyhow::Result<()> {
    let (_, contract, _, sk) = init_env().await;
    let predecessor_id = contract.id();
    let path = "testing-no-deposit";

    // Try to sign with no deposit, should fail.
    let msg = "without-deposit";
    let (payload_hash, respond_req, respond_resp) =
        create_response(predecessor_id, msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };

    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    // Responding to the request should fail with missing request because the deposit is too low,
    // so the request should have never made it into the request queue and subsequently the MPC network.
    let respond = contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    assert!(respond.into_result().unwrap_err().to_string().contains(
        &errors::MpcContractError::RespondError(errors::RespondError::RequestNotFound).to_string()
    ));

    let execution = status.await?;
    dbg!(&execution);
    assert!(execution.into_result().unwrap_err().to_string().contains(
        &errors::MpcContractError::SignError(errors::SignError::InsufficientDeposit(0, 1))
            .to_string()
    ));

    Ok(())
}

#[tokio::test]
async fn test_contract_initialization() -> anyhow::Result<()> {
    let (_, contract) = init().await;
    let valid_candidates = candidates(None);

    // Empty candidates should fail.
    let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": candidates
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with zero candidates or less than threshold candidates should fail"
    );

    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": valid_candidates,
        }))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "initializing with valid candidates should succeed"
    );

    // Reinitializing after the first successful initialization should fail.
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": valid_candidates,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}
