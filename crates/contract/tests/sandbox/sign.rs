use crate::sandbox::common::{
    candidates, create_message_payload_and_response, get_state, init, init_env, sign_and_validate,
    PARTICIPANT_LEN,
};
use mpc_contract::{
    crypto_shared::SignatureResponse,
    errors,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        participants::Participants,
        signature::{SignRequestArgs, SignatureRequest},
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_workspaces::{
    network::Sandbox,
    operations::TransactionStatus,
    result::{ExecutionFailure, ExecutionFinalResult, ExecutionResult},
    types::NearToken,
    Account, Contract, Worker,
};
use utilities::AccountIdExtV1;

use super::common::{submit_sign_request, submit_signature_response, SharedSecretKey};

// TODO: #1194 // this should be resolved
// Domain id 0 is always present if we have at least one domain on the contract.
// In all tests below we initialize at least one domain to test sign requests against.
const DOMAIN_ID_ZERO: DomainId = DomainId(0);
const ECDSA_PROTOCOLS: [SignatureScheme; 2] =
    [SignatureScheme::Secp256k1, SignatureScheme::V2Secp256k1];

pub struct SignatureTest {
    request_args: SignRequestArgs,
    expected_response: (SignatureRequest, SignatureResponse),
}

impl SignatureTest {
    pub fn new(account_id: &AccountId, domain_key: &DomainKey, msg: &str, path: &str) -> Self {
        let (payload, respond_req, respond_resp) = create_message_payload_and_response(
            domain_key.domain_config.id,
            account_id,
            msg,
            path,
            &domain_key.domain_secret_key,
        );
        let request_args = SignRequestArgs {
            payload_v2: Some(payload),
            path: path.to_string(),
            domain_id: Some(domain_key.domain_config.id),
            ..Default::default()
        };
        return SignatureTest {
            request_args,
            expected_response: (respond_req, respond_resp),
        };
    }

    pub async fn submit_sign_request(
        self: &SignatureTest,
        contract: &Contract,
        request_account: &Account,
    ) -> anyhow::Result<TransactionStatus> {
        submit_sign_request(request_account, &self.request_args, contract).await
    }

    pub async fn submit_reponse(
        self: &SignatureTest,
        contract: &Contract,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        submit_signature_response(
            &self.expected_response.0,
            &self.expected_response.1,
            contract,
            attested_account,
        )
        .await
    }

    pub fn verify_signature_timeout(
        self: &SignatureTest,
        execution: ExecutionFinalResult,
    ) -> anyhow::Result<()> {
        match execution.into_result() {
            Ok(_) => anyhow::bail!("expected timeout"),
            Err(err) => {
                if !err
                    .to_string()
                    .contains(&errors::RequestError::Timeout.to_string())
                {
                    anyhow::bail!("failed, but not due to timeout: {:#?}", err)
                }
            }
        }
        Ok(())
    }

    pub fn verify_signature_success(
        self: &SignatureTest,
        execution: ExecutionFinalResult,
    ) -> anyhow::Result<()> {
        let execution = execution.into_result()?;
        let returned_resp: SignatureResponse = execution.json()?;
        if returned_resp != self.expected_response.1 {
            anyhow::bail!(
                "Returned signature request does not match\n expected: {:#?}\n, found: {:#?}",
                self.expected_response.1,
                returned_resp
            );
        }
        Ok(())
    }

    pub async fn sign_and_validate(
        self: &SignatureTest,
        worker: &Worker<Sandbox>,
        contract: &Contract,
        request_account: &Account,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        let status = self.submit_sign_request(contract, request_account).await?;
        // race condition??
        status.
        let info = worker.tx_status(transaction_info, wait_until)
        // need to query transaction status
        //worker
        //    .tx_status(TransactionInfo


        //        worker,
        //        request_account.id(),
        //        status.hash(),
        //    ))
        //    .await;
        let rpc_resp = self
            .worker
            .client()
            .tx_async_status(
                &self.sender_id,
                near_primitives::hash::CryptoHash(self.hash.0),
                TxExecutionStatus::Included,
            )
            .await;
        worker.fast_forward(1).await.unwrap();
        self.submit_reponse(contract, attested_account).await?;
        let execution = status.await?;
        self.verify_signature_success(execution)?;
        Ok(())
    }

    pub async fn sign_and_timeout(
        self: &SignatureTest,
        worker: &Worker<Sandbox>,
        contract: &Contract,
        request_account: &Account,
    ) -> anyhow::Result<()> {
        let status = self.submit_sign_request(contract, request_account).await?;
        worker.fast_forward(200).await.unwrap();

        let execution = status.await?;
        self.verify_signature_timeout(execution)?;
        Ok(())
    }
}
//
// note, this solves: https://github.com/near/mpc/issues/1194, just in a different way (we query
// the contract interface, which is maybe even better).
pub struct DomainKey {
    domain_config: DomainConfig,
    domain_secret_key: SharedSecretKey,
}

// todo: simpler testing? use cases? Or run them in parallel...

// todo: split this into 3 tests: success, repeated requests and timeout
#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) = init_env(&ECDSA_PROTOCOLS, PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let path = "test";

    let alice = worker.dev_create_account().await.unwrap();
    let predecessor_id = alice.id();

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];
    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();

    for domain_idx in 0..domains.len() {
        //let domain_id = domains[domain_idx].id;
        let domain_key = DomainKey {
            domain_config: domains[domain_idx].clone(),
            domain_secret_key: sks[domain_idx].clone(),
        };
        for msg in messages {
            // some race condition?
            let signature_test =
                SignatureTest::new(&predecessor_id.as_v2_account_id(), &domain_key, msg, path);
            signature_test
                .sign_and_validate(&worker, &contract, &alice, &attested_account)
                .await
                .unwrap();
        }

        // check duplicate requests can also be signed: (this test is broken)
        let duplicate_msg = "welp";

        let signature_test = SignatureTest::new(
            &predecessor_id.as_v2_account_id(),
            &domain_key,
            duplicate_msg,
            path,
        );
        let first_request = signature_test
            .submit_sign_request(&contract, &alice)
            .await
            .unwrap();
        worker.fast_forward(1).await.unwrap();
        let second_request = signature_test
            .submit_sign_request(&contract, &alice)
            .await
            .unwrap();
        worker.fast_forward(1).await.unwrap();
        signature_test
            .submit_reponse(&contract, attested_account)
            .await
            .unwrap();
        // first request should fail, as only the most recent will be responded to
        signature_test
            .verify_signature_success(second_request.await.unwrap())
            .unwrap();
        worker.fast_forward(201).await.unwrap();
        signature_test
            .verify_signature_timeout(first_request.await.unwrap())
            .unwrap();

        let signature_test = SignatureTest::new(
            &predecessor_id.as_v2_account_id(),
            &domain_key,
            "This signature request should time out",
            path,
        );
        // a request without a response should fail
        // //, as only the most recent will be responded to
        // worker.fast_forward(1).await.unwrap();
        signature_test
            .sign_and_timeout(&worker, &contract, &alice)
            .await
            .unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_sign_success_refund() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) = init_env(&ECDSA_PROTOCOLS, PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";
    let msg = "hello world!";

    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();

    for domain_idx in 0..domains.len() {
        let domain_key = DomainKey {
            domain_config: domains[domain_idx].clone(),
            domain_secret_key: sks[domain_idx].clone(),
        };

        let signature_test =
            SignatureTest::new(&alice.id().as_v2_account_id(), &domain_key, &msg, &path);
        signature_test
            .sign_and_validate(&worker, &contract, &alice, &attested_account)
            .await
            .unwrap();

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
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_sign_fail_refund() -> anyhow::Result<()> {
    let (worker, contract, _, sks) = init_env(&ECDSA_PROTOCOLS, PARTICIPANT_LEN).await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");

    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();

    for domain_idx in 0..domains.len() {
        let domain_key = DomainKey {
            domain_config: domains[domain_idx].clone(),
            domain_secret_key: sks[domain_idx].clone(),
        };

        let signature_test =
            SignatureTest::new(&alice.id().as_v2_account_id(), &domain_key, &msg, &path);
        let err = signature_test
            .sign_and_timeout(&worker, &contract, &alice)
            .await
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
        assert!(balance >= new_balance, "user balance should not increase");
        assert!(
            balance.as_millinear() - new_balance.as_millinear() < 10,
            "refund should happen"
        );
        assert!(
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_deposits() -> anyhow::Result<()> {
    let (_, contract, mpc_nodes, sks) = init_env(&ECDSA_PROTOCOLS, PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let predecessor_id = contract.id();
    let path = "testing-no-deposit";

    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();

    for domain_idx in 0..domains.len() {
        let domain_key = DomainKey {
            domain_config: domains[domain_idx].clone(),
            domain_secret_key: sks[domain_idx].clone(),
        };
        let domain_id = domains[domain_idx].id;
        let domain_secret_key = &sks[domain_idx];
        // Try to sign with no deposit, should fail.
        let msg = "without-deposit";
        let (payload, respond_req, respond_resp) = create_message_payload_and_response(
            domain_id,
            &predecessor_id.as_v2_account_id(),
            msg,
            path,
            domain_secret_key,
        );
        let request = SignRequestArgs {
            payload_v2: Some(payload),
            path: path.into(),
            domain_id: Some(domain_id),
            ..Default::default()
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

        // todo: we are not testing anything here below
        // Responding to the request should fail with missing request because the deposit is too low,
        // so the request should have never made it into the request queue and subsequently the MPC network.
        let respond = attested_account
            .call(contract.id(), "respond")
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
    }

    Ok(())
}

#[tokio::test]
async fn test_sign_v1_compatibility() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];
    let predecessor_id = contract.id();
    let path = "test";

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();

    for domain_idx in 0..domains.len() {
        let domain_key = DomainKey {
            domain_config: domains[domain_idx].clone(),
            domain_secret_key: sks[domain_idx].clone(),
        };
        let domain_id = domains[domain_idx].id;
        let domain_secret_key = &sks[domain_idx];
        for msg in messages {
            println!("submitting: {msg}");
            let (payload, respond_req, respond_resp) = create_message_payload_and_response(
                domain_id,
                &predecessor_id.as_v2_account_id(),
                msg,
                path,
                domain_secret_key,
            );
            let status = contract
                .call("sign")
                .args_json(serde_json::json!({
                    "request": {
                        "payload": *payload.as_ecdsa().unwrap(),
                        "path": path,
                        "key_version": 0,
                    },
                }))
                .deposit(NearToken::from_yoctonear(1))
                .max_gas()
                .transact_async()
                .await?;
            dbg!(&status);

            worker.fast_forward(1).await.unwrap();

            // Call `respond` as if we are the MPC network itself.
            let respond = attested_account
                .call(contract.id(), "respond")
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
            let returned_resp: SignatureResponse = execution.json()?;
            assert_eq!(
                returned_resp, respond_resp,
                "Returned signature request does not match"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_initialization() -> anyhow::Result<()> {
    let (_, contract) = init().await;

    // Empty candidates should fail.
    let participants = Participants::new();
    let threshold = Threshold::new(0);
    let proposed_parameters = ThresholdParameters::new_unvalidated(participants, threshold);
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with zero candidates or less than threshold candidates should fail"
    );

    let proposed_parameters =
        ThresholdParameters::new(candidates(None), Threshold::new(3)).unwrap();
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
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
            "parameters": proposed_parameters,
            "config": "null",
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_eddsa() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Ed25519], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let path = "test";

    let alice = worker.dev_create_account().await.unwrap();
    let predecessor_id = alice.id();

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    let state = get_state(&contract).await;
    let domains = state.domain_registry().unwrap().domains();
    let domain_key = DomainKey {
        domain_config: domains[0].clone(),
        domain_secret_key: sks[0].clone(),
    };
    // sanityc check
    assert_eq!(domain_key.domain_config.scheme, SignatureScheme::Ed25519);
    for msg in messages {
        println!("submitting: {msg}");
        let (payload, respond_req, respond_resp) = create_message_payload_and_response(
            DOMAIN_ID_ZERO,
            &predecessor_id.as_v2_account_id(),
            msg,
            path,
            &sks[0],
        );

        let request = SignRequestArgs {
            payload_v2: Some(payload),
            path: path.into(),
            domain_id: Some(DOMAIN_ID_ZERO),
            ..Default::default()
        };

        sign_and_validate(
            &worker,
            &alice,
            &request,
            Some((&respond_req, &respond_resp)),
            &contract,
            attested_account,
        )
        .await?;
    }

    // check duplicate requests can also be signed:
    let duplicate_msg = "welp";
    let (payload, respond_req, respond_resp) = create_message_payload_and_response(
        DOMAIN_ID_ZERO,
        &predecessor_id.as_v2_account_id(),
        duplicate_msg,
        path,
        &sks[0],
    );
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DOMAIN_ID_ZERO),
        ..Default::default()
    };
    sign_and_validate(
        &worker,
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;
    sign_and_validate(
        &worker,
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;

    // Check that a sign with no response from MPC network properly errors out:
    let err = sign_and_validate(&worker, &alice, &request, None, &contract, attested_account)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    Ok(())
}
