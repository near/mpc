use crypto_shared::kdf::{check_ec_signature, derive_secret_key};
use crypto_shared::{
    derive_epsilon, derive_key, ScalarExt as _, SerializableAffinePoint, SerializableScalar,
    SignatureResponse,
};
use ecdsa::signature::Verifier;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldBytes, Scalar, Secp256k1};
use mpc_contract::errors;
use mpc_contract::primitives::{
    CandidateInfo, ParticipantInfo, Participants, SignRequest, SignatureRequest,
};
use near_sdk::NearToken;
use near_workspaces::network::Sandbox;
use near_workspaces::{AccountId, Contract, Worker};
use signature::digest::{Digest, FixedOutput};
use signature::DigestSigner;

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

const CONTRACT_FILE_PATH: &str = "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

fn candidates() -> HashMap<AccountId, CandidateInfo> {
    let mut candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();
    for account_id in ["alice.near", "bob.near", "caesar.near"] {
        candidates.insert(
            AccountId::from_str(account_id).unwrap(),
            CandidateInfo {
                account_id: AccountId::from_str(account_id).unwrap(),
                url: "127.0.0.1".into(),
                cipher_pk: [0; 32],
                sign_pk: near_sdk::PublicKey::from_str(
                    "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
                )
                .unwrap(),
            },
        );
    }
    candidates
}

async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = std::fs::read(CONTRACT_FILE_PATH).unwrap();
    let contract = worker.dev_deploy(&wasm).await.unwrap();
    (worker, contract)
}

async fn init_with_candidates(pk: Option<near_crypto::PublicKey>) -> (Worker<Sandbox>, Contract) {
    let (worker, contract) = init().await;
    let candidates = candidates();

    let init = if let Some(pk) = pk {
        let participants_map = candidates
            .into_iter()
            .map(|(k, v)| (k, Into::<ParticipantInfo>::into(v)))
            .collect::<BTreeMap<_, _>>();
        let participants = Participants {
            next_id: participants_map.len().try_into().unwrap(),
            participants: participants_map.clone(),
            account_to_participant_id: participants_map
                .into_iter()
                .enumerate()
                .map(|(id, (account_id, _))| (account_id, id.try_into().unwrap()))
                .collect(),
        };
        contract
            .call("init_running")
            .args_json(serde_json::json!({
                "epoch": 0,
                "threshold": 2,
                "participants": participants,
                "public_key": pk,
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap()
    } else {
        contract
            .call("init")
            .args_json(serde_json::json!({
                "threshold": 2,
                "candidates": candidates
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap()
    };
    dbg!(init);
    (worker, contract)
}

async fn init_env() -> (Worker<Sandbox>, Contract, k256::SecretKey) {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let (worker, contract) = init_with_candidates(Some(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(
            &pk.as_affine().to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap(),
    )))
    .await;

    (worker, contract, sk)
}

/// Process the message, creating the same hash with type of Digest, Scalar, and [u8; 32]
async fn process_message(msg: &str) -> (impl Digest, k256::Scalar, [u8; 32]) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();
    let scalar_hash =
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &bytes,
        );

    let payload_hash: [u8; 32] = bytes.into();
    (digest, scalar_hash, payload_hash)
}

async fn create_response(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &k256::SecretKey,
) -> ([u8; 32], SignatureRequest, SignatureResponse) {
    let (digest, scalar_hash, payload_hash) = process_message(msg).await;
    let pk = sk.public_key();

    let epsilon = derive_epsilon(predecessor_id, path);
    let derived_sk = derive_secret_key(sk, epsilon);
    let derived_pk = derive_key(pk.into(), epsilon);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let payload_hash_s = Scalar::from_bytes(payload_hash).unwrap();
    let respond_req = SignatureRequest::new(payload_hash_s, predecessor_id, path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, scalar_hash, 0).is_ok() {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, scalar_hash, 1).is_ok() {
        1
    } else {
        panic!("unable to use recovery id of 0 or 1");
    };

    let respond_resp = SignatureResponse {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id,
    };

    (payload_hash, respond_req, respond_resp)
}

async fn sign_and_validate(
    request: &SignRequest,
    respond: Option<(&SignatureRequest, &SignatureResponse)>,
    contract: &Contract,
) -> anyhow::Result<()> {
    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if let Some((respond_req, respond_resp)) = respond {
        // Call `respond` as if we are the MPC network itself.
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
    }

    let execution = status.await?;
    dbg!(&execution);
    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: SignatureResponse = execution.json()?;
    if let Some((_, respond_resp)) = respond {
        assert_eq!(
            &returned_resp, respond_resp,
            "Returned signature request does not match"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let (_, contract, sk) = init_env().await;
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
    let (_, contract, sk) = init_env().await;
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
    let valid_candidates = candidates();

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
