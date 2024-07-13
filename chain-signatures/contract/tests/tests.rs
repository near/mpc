use crypto_shared::kdf::{check_ec_signature, derive_secret_key};
use crypto_shared::{
    derive_epsilon, derive_key, SerializableAffinePoint, SerializableScalar, SignatureResponse,
};
use ecdsa::signature::Verifier;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldBytes, Secp256k1};
use mpc_contract::primitives::{CandidateInfo, ParticipantInfo, SignRequest};
use near_sdk::NearToken;
use near_workspaces::network::Sandbox;
use near_workspaces::{AccountId, Contract, Worker};
use signature::digest::{Digest, FixedOutput};
use signature::DigestSigner;

use std::collections::HashMap;
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

    let result = if let Some(pk) = pk {
        let participants = candidates
            .into_iter()
            .map(|(k, v)| (k, Into::<ParticipantInfo>::into(v)))
            .collect::<HashMap<_, _>>();
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
            .unwrap();
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
            .unwrap();
    };
    dbg!(result);
    (worker, contract)
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

#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();

    let (_, contract) = init_with_candidates(Some(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(
            &pk.as_affine().to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap(),
    )))
    .await;
    let predecessor_id = contract.id();
    let path = "test".to_string();

    let msg = b"hello world";
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);

    let epsilon = derive_epsilon(predecessor_id, &path);
    let derived_sk = derive_secret_key(&sk, epsilon);
    let derived_pk = derive_key(pk.into(), epsilon);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let signature: ecdsa::Signature<Secp256k1> =
        signing_key.try_sign_digest(digest.clone()).unwrap();
    verifying_key.verify(&msg[..], &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();

    let bytes: FieldBytes = digest.finalize_fixed();
    let scalar_hash =
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &bytes,
        );
    let payload_hash: [u8; 32] = bytes.into();

    let respond_req = mpc_contract::SignatureRequest::new(payload_hash, &predecessor_id, &path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = s.as_ref().clone();

    let expected_public_key = derive_key(pk.into(), respond_req.epsilon.scalar);
    let recovery_id =
        if check_ec_signature(&expected_public_key, &big_r, &s, scalar_hash, 0).is_ok() {
            0
        } else if check_ec_signature(&expected_public_key, &big_r, &s, scalar_hash, 1).is_ok() {
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

    let request = SignRequest {
        payload: payload_hash,
        path,
        key_version: 0,
    };

    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;

    // Call `respond` as if we are the MPC network itself.
    contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Finally wait the result:
    let execution = status.await?;
    println!("{execution:#?}");


    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;

    // yield resume should have a max limit of about 200. Let's get as close as possible to test out this
    // boundary and see if it fails:
    let blocks_to_wait = 195;
    tokio::time::sleep(tokio::time::Duration::from_secs(blocks_to_wait)).await;

    // Call `respond` as if we are the MPC network itself.
    contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let execution = status.await?;
    println!("{execution:#?}");


    Ok(())
}
