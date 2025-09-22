use crate::common::{
    create_response_ckd, derive_confidential_key_and_validate, example_secp256k1_point,
    init_env_secp256k1,
};
use mpc_contract::{
    crypto_shared::CKDResponse,
    errors,
    primitives::{ckd::CKDRequestArgs, domain::DomainId},
};
use near_sdk::AccountId;
use near_workspaces::{network::Sandbox, result::Execution, types::NearToken, Account, Worker};

async fn create_account_given_id(
    worker: &Worker<Sandbox>,
    account_id: AccountId,
) -> Result<Execution<Account>, near_workspaces::error::Error> {
    let (_, sk) = worker.generate_dev_account_credentials();
    worker.create_root_account_subaccount(account_id, sk).await
}

#[tokio::test]
async fn test_contract_ckd_request() -> anyhow::Result<()> {
    let (worker, contract, _, sks) = init_env_secp256k1(1).await;
    let sk = match &sks[0] {
        crate::common::SharedSecretKey::Secp256k1(sk) => sk,
        crate::common::SharedSecretKey::Ed25519(_) => unreachable!(),
    };

    let account_ids: [AccountId; 4] = [
        "this_is_an_app".parse().unwrap(),
        "another".parse().unwrap(),
        "a_better_one".parse().unwrap(),
        "a_fake_one".parse().unwrap(),
    ];

    let app_public_key: near_sdk::PublicKey = example_secp256k1_point();

    for account_id in account_ids {
        let account = create_account_given_id(&worker, account_id.clone())
            .await
            .unwrap()
            .unwrap();

        println!("submitting: {account_id}");

        let request = CKDRequestArgs {
            app_public_key: app_public_key.clone(),
            domain_id: DomainId::default(),
        };

        let (respond_req, respond_resp) =
            create_response_ckd(account.id(), app_public_key.clone(), &request.domain_id, sk);

        derive_confidential_key_and_validate(
            account,
            &request,
            Some((&respond_req, &respond_resp)),
            &contract,
        )
        .await?;
    }

    // check duplicate requests
    let account_id: AccountId = "duplicate".parse().unwrap();
    let account = create_account_given_id(&worker, account_id.clone())
        .await
        .unwrap()
        .unwrap();
    let request = CKDRequestArgs {
        app_public_key: app_public_key.clone(),
        domain_id: DomainId::default(),
    };
    let (respond_req, respond_resp) =
        create_response_ckd(account.id(), app_public_key, &request.domain_id, sk);

    derive_confidential_key_and_validate(
        account.clone(),
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
    )
    .await?;
    derive_confidential_key_and_validate(
        account.clone(),
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
    )
    .await?;

    // Check that a ckd with no response from MPC network properly errors out:
    let err = derive_confidential_key_and_validate(account, &request, None, &contract)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_contract_ckd_success_refund() -> anyhow::Result<()> {
    let (worker, contract, _, sks) = init_env_secp256k1(1).await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let sk = match &sks[0] {
        crate::common::SharedSecretKey::Secp256k1(sk) => sk,
        crate::common::SharedSecretKey::Ed25519(_) => unreachable!(),
    };
    let app_public_key: near_sdk::PublicKey = example_secp256k1_point();
    let request = CKDRequestArgs {
        app_public_key: app_public_key.clone(),
        domain_id: DomainId::default(),
    };

    let (respond_req, respond_resp) =
        create_response_ckd(alice.id(), app_public_key, &request.domain_id, sk);

    let status = alice
        .call(contract.id(), "request_app_private_key")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Call `respond_ckd` as if we are the MPC network itself.
    let respond = contract
        .call("respond_ckd")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);

    let execution = status.await?;
    dbg!(&execution);

    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: CKDResponse = execution.json()?;
    assert_eq!(
        returned_resp, respond_resp,
        "Returned ckd request does not match"
    );

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_millinear(),
        new_contract_balance.as_millinear(),
    );
    assert!(
        contract_balance.as_millinear() - new_contract_balance.as_millinear() < 20,
        "respond should take less than 0.02 NEAR"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_ckd_fail_refund() -> anyhow::Result<()> {
    let (worker, contract, _, _) = init_env_secp256k1(1).await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let app_public_key: near_sdk::PublicKey = example_secp256k1_point();
    let request = CKDRequestArgs {
        app_public_key,
        domain_id: DomainId::default(),
    };

    let status = alice
        .call(contract.id(), "request_app_private_key")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // we do not respond, ckd will fail due to timeout
    let execution = status.await;
    dbg!(&execution);
    let err = execution
        .unwrap()
        .into_result()
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_yoctonear(),
        new_contract_balance.as_yoctonear(),
    );
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    assert!(
        contract_balance.as_millinear() - new_contract_balance.as_millinear() <= 1,
        "refund transfer should take less than 0.001 NEAR"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_ckd_request_deposits() -> anyhow::Result<()> {
    let (worker, contract, _, sks) = init_env_secp256k1(1).await;
    let alice = worker.dev_create_account().await?;
    let sk = match &sks[0] {
        crate::common::SharedSecretKey::Secp256k1(sk) => sk,
        crate::common::SharedSecretKey::Ed25519(_) => unreachable!(),
    };
    let app_public_key: near_sdk::PublicKey = example_secp256k1_point();
    let request = CKDRequestArgs {
        app_public_key: app_public_key.clone(),
        domain_id: DomainId::default(),
    };

    let status = contract
        .call("request_app_private_key")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    let (respond_req, respond_resp) =
        create_response_ckd(alice.id(), app_public_key, &request.domain_id, sk);
    // Responding to the request should fail with missing request because the deposit is too low,
    // so the request should have never made it into the request queue and subsequently the MPC network.
    let respond = contract
        .call("respond_ckd")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    assert!(respond
        .into_result()
        .unwrap_err()
        .to_string()
        .contains(&errors::InvalidParameters::RequestNotFound.to_string()));

    let execution = status.await?;
    dbg!(&execution);
    assert!(execution
        .into_result()
        .unwrap_err()
        .to_string()
        .contains(&errors::InvalidParameters::InsufficientDeposit.to_string()));

    Ok(())
}
