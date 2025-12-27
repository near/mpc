use super::consts::DEFAULT_MAX_TIMEOUT_TX_INCLUDED;
use super::interface::{IntoContractType, IntoInterfaceType};
use super::shared_key_utils::{
    derive_secret_key_ed25519, derive_secret_key_secp256k1, generate_random_app_public_key,
    DomainKey, SharedSecretKey,
};
use contract_interface::types::{self as dtos};
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier as _;
use elliptic_curve::{Field as _, Group as _};
use k256::{elliptic_curve::point::DecompressPoint as _, AffinePoint, FieldBytes, Secp256k1};
use mpc_contract::{
    crypto_shared::{
        derive_key_secp256k1, derive_tweak, ed25519_types, k256_types,
        k256_types::SerializableAffinePoint, kdf::check_ec_signature, kdf::derive_app_id,
        CKDResponse, SerializableScalar, SignatureResponse,
    },
    errors,
    primitives::{
        ckd::{CKDRequest, CKDRequestArgs},
        domain::{DomainId, SignatureScheme},
        signature::{Bytes, Payload, SignRequestArgs, SignatureRequest, YieldIndex},
    },
};
use near_account_id::AccountId;
use near_workspaces::{
    network::Sandbox, operations::TransactionStatus, types::NearToken, Account, Contract, Worker,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rand_core::CryptoRngCore;
use serde::Serialize;
use sha2::Sha256;
use signature::DigestSigner;
use std::time::Duration;
use threshold_signatures::{
    confidential_key_derivation::{self as ckd, hash_app_id_with_pk, BLS12381SHA256},
    ecdsa as ts_ecdsa, eddsa,
    frost_ed25519::{self},
    KeygenOutput,
};
use utilities::AccountIdExtV1;

#[derive(Serialize)]
pub struct SignResponseArgs {
    pub request: SignatureRequest,
    pub response: SignatureResponse,
}

impl SignResponseArgs {
    pub fn json_args(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }
}

pub struct SignRequestTest {
    pub response: SignResponseArgs,
    pub args: SignRequestArgs,
}

impl SignRequestTest {
    pub fn new(
        domain_key: &DomainKey,
        predecessor_id: &AccountId,
        msg: &str,
        path: &str,
    ) -> SignRequestTest {
        let domain_id = domain_key.domain_config.id;
        let (payload, request, response) = match &domain_key.domain_secret_key {
            SharedSecretKey::Secp256k1(sk) => {
                create_response_secp256k1(domain_id, predecessor_id, msg, path, sk)
            }
            SharedSecretKey::Ed25519(sk) => {
                create_response_ed25519(domain_id, predecessor_id, msg, path, sk)
            }
            SharedSecretKey::Bls12381(_) => {
                // todo: make SignRequestTest an enum
                unreachable!()
            }
        };
        let args = SignRequestArgs {
            payload_v2: Some(payload.clone()),
            path: path.into(),
            domain_id: Some(domain_key.domain_id()),
            ..Default::default()
        };
        SignRequestTest {
            response: SignResponseArgs { request, response },
            args,
        }
    }

    pub fn expected_response(&self) -> &SignatureResponse {
        &self.response.response
    }

    pub fn request_json_args(&self) -> serde_json::Value {
        serde_json::json!({
            "request": self.args,
        })
    }

    pub fn payload(&self) -> &Payload {
        &self.response.request.payload
    }

    pub async fn verify_execution_outcome(&self, status: TransactionStatus) -> anyhow::Result<()> {
        let execution = status.await?;
        dbg!(&execution);
        let execution = execution.into_result()?;
        let returned_resp: SignatureResponse = execution.json()?;
        assert_eq!(
            &returned_resp, &self.response.response,
            "Returned signature request does not match"
        );
        Ok(())
    }

    pub async fn verify_timeout(&self, status: TransactionStatus) -> anyhow::Result<()> {
        let execution = status.await?;
        dbg!(&execution);
        assert!(execution.is_failure());
        let err = execution
            .into_result()
            .expect_err("expect execution failure");
        assert!(err
            .to_string()
            .contains(&errors::RequestError::Timeout.to_string()));
        Ok(())
    }

    pub async fn sign_ensure_included(
        &self,
        account: &Account,
        contract: &Contract,
    ) -> anyhow::Result<TransactionStatus> {
        let status = submit_sign_request(account, &self.args, contract).await?;
        await_request_in_contract_queue(contract, &self.response.request, None).await?;
        Ok(status)
    }

    pub async fn sign_and_validate(
        &self,
        account: &Account,
        contract: &Contract,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        let status = self.sign_ensure_included(account, contract).await?;
        submit_signature_response(&self.response, contract, attested_account).await?;
        self.verify_execution_outcome(status).await
    }
}

// contract interactions
pub async fn submit_sign_request(
    account: &Account,
    request: &SignRequestArgs,
    contract: &Contract,
) -> anyhow::Result<TransactionStatus> {
    let status = account
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    Ok(status)
}

pub async fn submit_ckd_request(
    account: &Account,
    request: &CKDRequestArgs,
    contract: &Contract,
) -> anyhow::Result<TransactionStatus> {
    let status = account
        .call(contract.id(), "request_app_private_key")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    Ok(status)
}

pub async fn submit_signature_response(
    response: &SignResponseArgs,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    // Call `respond` as if we are an attested_account
    let respond = attested_account
        .call(contract.id(), "respond")
        .args_json(response.json_args())
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    respond.into_result()?;
    Ok(())
}

pub async fn submit_ckd_response(
    respond_req: &CKDRequest,
    respond_resp: &CKDResponse,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    // Call `respond` as if we are an attested_account
    let respond = attested_account
        .call(contract.id(), "respond_ckd")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);

    Ok(())
}

// contract state queries
pub async fn request_is_in_queue(
    contract: &Contract,
    request: &SignatureRequest,
) -> Option<YieldIndex> {
    contract
        .view("get_pending_request")
        .args_json(serde_json::json!({"request": request}))
        .await
        .unwrap()
        .json()
        .unwrap()
}

pub async fn await_request_in_contract_queue(
    contract: &Contract,
    request: &SignatureRequest,
    max_timeout: Option<Duration>,
) -> anyhow::Result<()> {
    let timeout = max_timeout.unwrap_or(DEFAULT_MAX_TIMEOUT_TX_INCLUDED);
    let start = std::time::Instant::now();

    loop {
        if request_is_in_queue(contract, request).await.is_some() {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for request to appear in queue");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Derives a confidential key following https://github.com/near/threshold-signatures/blob/main/docs/confidential_key_derivation.md
pub fn create_response_ckd(
    account_id: &AccountId,
    app_public_key: dtos::Bls12381G1PublicKey,
    domain_id: &DomainId,
    key_package: &KeygenOutput<BLS12381SHA256>,
    derivation_path: &str,
) -> (CKDRequest, CKDResponse) {
    let request = CKDRequest::new(
        app_public_key.clone(),
        *domain_id,
        account_id,
        derivation_path,
    );

    let app_id = derive_app_id(account_id, derivation_path);
    let app_pk: ckd::ElementG1 = app_public_key.into_contract_type();
    let msk = key_package.private_share.to_scalar();

    let big_s = hash_app_id_with_pk(&key_package.public_key, app_id.as_ref()) * msk;
    let y = ckd::Scalar::random(OsRng);
    let big_y = ckd::ElementG1::generator() * y;
    let big_c = big_s + app_pk * y;

    let response = CKDResponse {
        big_y: big_y.into_interface_type(),
        big_c: big_c.into_interface_type(),
    };
    (request, response)
}

// contract calls
pub async fn derive_confidential_key_and_validate(
    account: Account,
    request: &CKDRequestArgs,
    respond: Option<(&CKDRequest, &CKDResponse)>,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    let status = account
        .call(contract.id(), "request_app_private_key")
        .args_json(serde_json::json!({ "request": request }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if let Some((respond_req, respond_resp)) = respond {
        assert_eq!(
            derive_app_id(&account.id().as_v2_account_id(), &request.derivation_path),
            respond_req.app_id
        );
        let respond = attested_account
            .call(contract.id(), "respond_ckd")
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
    let returned_resp: CKDResponse = execution.json()?;
    if let Some((_, respond_resp)) = respond {
        assert_eq!(
            &returned_resp, respond_resp,
            "Returned ckd request does not match"
        );
    }
    Ok(())
}

pub async fn make_and_submit_requests(
    keys: &[DomainKey],
    contract: &Contract,
    worker: &Worker<Sandbox>,
    rng: &mut impl CryptoRngCore,
) -> (Vec<PendingSignRequest>, Vec<PendingCKDRequest>) {
    let mut pending_sign_requests = vec![];
    let mut pending_ckd_requests = vec![];
    let path = "test";

    let signature_request_payloads = [
        generate_random_request_payloads(10, rng),
        generate_random_request_payloads(4, rng),
    ];
    let app_public_keys = [
        generate_random_app_public_key(rng),
        generate_random_app_public_key(rng),
    ];

    let alice = worker.dev_create_account().await.unwrap();
    let alice_id = alice.id().as_v2_account_id();

    for key in keys {
        match key.domain_config.scheme {
            SignatureScheme::Secp256k1
            | SignatureScheme::Ed25519
            | SignatureScheme::V2Secp256k1 => {
                for message in &signature_request_payloads {
                    let req = SignRequestTest::new(key, &alice_id, message, path);
                    let transaction = submit_sign_request(&alice, &req.args, contract)
                        .await
                        .unwrap();
                    pending_sign_requests.push(PendingSignRequest {
                        transaction,
                        response: req.response,
                    });
                }
            }
            SignatureScheme::Bls12381 => {
                for app_public_key in &app_public_keys {
                    let SharedSecretKey::Bls12381(sk) = &key.domain_secret_key else {
                        unreachable!();
                    };
                    let (ckd_request, ckd_response) = create_response_ckd(
                        &alice_id,
                        app_public_key.clone(),
                        &key.domain_id(),
                        sk,
                        path,
                    );
                    let request_args = CKDRequestArgs {
                        derivation_path: path.to_string(),
                        app_public_key: app_public_key.clone(),
                        domain_id: key.domain_id(),
                    };
                    let transaction = submit_ckd_request(&alice, &request_args, contract)
                        .await
                        .unwrap();

                    pending_ckd_requests.push(PendingCKDRequest {
                        transaction,
                        ckd_request,
                        ckd_response,
                    });
                }
            }
        }
    }
    (pending_sign_requests, pending_ckd_requests)
}

fn generate_random_request_payloads(n: usize, rng: &mut impl CryptoRngCore) -> String {
    (0..n).map(|_| rng.sample(Alphanumeric) as char).collect()
}

pub fn create_response_secp256k1(
    domain_id: DomainId,
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &ts_ecdsa::KeygenOutput,
) -> (Payload, SignatureRequest, SignatureResponse) {
    let (digest, payload) = process_message(msg);
    let pk = signing_key.public_key;

    let tweak = derive_tweak(predecessor_id, path);
    let derived_sk = derive_secret_key_secp256k1(signing_key, &tweak);
    let derived_pk = derive_key_secp256k1(&pk.to_element().to_affine(), &tweak).unwrap();
    let signing_key =
        k256::ecdsa::SigningKey::from_bytes(&derived_sk.private_share.to_scalar().into()).unwrap();
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let respond_req = SignatureRequest::new(domain_id, payload.clone(), predecessor_id, path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, payload.as_ecdsa().unwrap(), 0)
        .is_ok()
    {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, payload.as_ecdsa().unwrap(), 1).is_ok() {
        1
    } else {
        panic!("unable to use recovery id of 0 or 1");
    };

    let respond_resp = SignatureResponse::Secp256k1(k256_types::Signature {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id,
    });

    (payload, respond_req, respond_resp)
}

pub fn create_response_ed25519(
    domain_id: DomainId,
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &eddsa::KeygenOutput,
) -> (Payload, SignatureRequest, SignatureResponse) {
    let tweak = derive_tweak(predecessor_id, path);
    let derived_signing_key = derive_secret_key_ed25519(signing_key, &tweak);

    let payload: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        hasher.clone().finalize().into()
    };

    let derived_signing_key =
        frost_ed25519::SigningKey::from_scalar(derived_signing_key.private_share.to_scalar())
            .unwrap();

    let signature = derived_signing_key
        .sign(OsRng, &payload)
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let bytes = Bytes::new(payload.into()).unwrap();
    let payload = Payload::Eddsa(bytes);

    let respond_req = SignatureRequest::new(domain_id, payload.clone(), predecessor_id, path);

    let signature_response = SignatureResponse::Ed25519 {
        signature: ed25519_types::Signature::new(signature),
    };

    (payload, respond_req, signature_response)
}

/// Process the message, creating the same hash with type of [`Digest`] and [`Payload`]
pub fn process_message(msg: &str) -> (impl Digest, Payload) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = Payload::from_legacy_ecdsa(bytes.into());
    (digest, payload_hash)
}

pub struct PendingSignRequest {
    pub transaction: TransactionStatus,
    pub response: SignResponseArgs,
}

pub struct PendingCKDRequest {
    pub transaction: TransactionStatus,
    pub ckd_request: CKDRequest,
    pub ckd_response: CKDResponse,
}
