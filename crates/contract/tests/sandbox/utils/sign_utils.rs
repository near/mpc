use crate::sandbox::utils::sandbox_mpc_contract::SandboxMpcContract;
use crate::sandbox::utils::sandbox_self_caller::{POLL_INTERVAL, SandboxSelfCaller};
use crate::sandbox::utils::transactions::CallMpcContract;

use super::consts::DEFAULT_MAX_TIMEOUT_TX_INCLUDED;
use super::shared_key_utils::{
    DomainKey, SharedSecretKey, derive_secret_key_ed25519, derive_secret_key_secp256k1,
    generate_random_app_public_key,
};
use anyhow::Context as _;
use digest::{Digest, FixedOutput};
use k256::{
    FieldBytes,
    elliptic_curve::{Field as _, Group as _},
};
use mpc_contract::errors;
use near_account_id::AccountId;
use near_contract_transport::watch::{Subscribe, wait_for};
use near_kit_primitives::View;
use near_mpc_contract_interface::call_args::{CKDRespondArgs, SignatureRespondArgs};
use near_mpc_contract_interface::contract::gas;
use near_mpc_contract_interface::types::kdf::{derive_app_id, derive_tweak};
use near_mpc_contract_interface::types::{
    self as dtos, CKDAppPublicKey, CKDAppPublicKeyPV, CKDRequestArgs,
};
use near_mpc_contract_interface::types::{
    CKDRequest, CKDResponse, DomainId, Payload, SignatureRequest, YieldIndex,
};
use near_mpc_sdk::sign::{Ed25519Signature, K256Signature};
use near_mpc_sdk::sign::{SignRequestArgs, SignRequestBuilder, SignatureRequestResponse};
use near_workspaces::{Account, Worker, network::Sandbox, operations::TransactionStatus};
use rand::{Rng, rngs::OsRng};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use signature::DigestSigner;
use std::time::Duration;
use threshold_signatures::{
    KeygenOutput,
    confidential_key_derivation::{self as ckd, BLS12381SHA256, hash_app_id_with_pk},
    ecdsa as ts_ecdsa,
    frost::eddsa,
    frost_ed25519::{self},
};

#[derive(Debug)]
#[expect(clippy::large_enum_variant)]
pub enum DomainResponseTest {
    Sign(SignRequestTest),
    CKD(CKDRequestTest),
}

impl DomainResponseTest {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        domain_key: &DomainKey,
        predecessor_id: &AccountId,
    ) -> Self {
        let domain_id = domain_key.domain_config.id;
        match &domain_key.domain_secret_key {
            SharedSecretKey::Secp256k1(sk) => DomainResponseTest::Sign(gen_secp_256k1_sign_test(
                rng,
                domain_id,
                predecessor_id,
                sk,
            )),
            SharedSecretKey::Ed25519(sk) => {
                DomainResponseTest::Sign(gen_ed25519_sign_test(rng, domain_id, predecessor_id, sk))
            }
            SharedSecretKey::Bls12381(sk) => {
                DomainResponseTest::CKD(CKDRequestTest::new(rng, domain_id, predecessor_id, sk))
            }
        }
    }

    pub async fn run(
        &self,
        account: &Account,
        contract: &SandboxMpcContract,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        let status = self
            .submit_request_ensure_included(account, contract)
            .await?;
        self.submit_response(contract, attested_account).await?;
        self.verify_execution_outcome(status).await?;
        Ok(())
    }

    pub async fn submit_response(
        &self,
        contract: &SandboxMpcContract,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        match &self {
            Self::Sign(inner) => {
                submit_signature_response(&inner.response, contract, attested_account).await
            }
            Self::CKD(inner) => {
                submit_ckd_response(&inner.response, contract, attested_account).await
            }
        }
    }

    pub async fn submit_request_ensure_included(
        &self,
        account: &Account,
        contract: &SandboxMpcContract,
    ) -> anyhow::Result<TransactionStatus> {
        let handle = account.call_mpc_async(contract.id());
        match self {
            Self::Sign(inner) => {
                let status = handle.sign(inner.args.clone()).await?;
                await_request_in_contract_queue(
                    contract.get_pending_request(&inner.response.request),
                )
                .await?;
                Ok(status)
            }
            Self::CKD(inner) => {
                let status = handle
                    .request_app_private_key(inner.args.clone())
                    .gas(gas::request_app_private_key(&inner.args))
                    .await?;
                await_request_in_contract_queue(
                    contract.get_pending_ckd_request(&inner.response.request),
                )
                .await?;
                Ok(status)
            }
        }
    }

    pub async fn verify_execution_outcome(&self, status: TransactionStatus) -> anyhow::Result<()> {
        match self {
            Self::Sign(inner) => inner.verify_execution_outcome(status).await,
            Self::CKD(inner) => inner.verify_execution_outcome(status).await,
        }
    }
}

#[derive(Debug)]
pub struct SignRequestTest {
    pub response: SignatureRespondArgs,
    pub args: SignRequestArgs,
}

impl SignRequestTest {
    pub fn request_json_args(&self) -> serde_json::Value {
        serde_json::json!({
            "request": self.args,
        })
    }

    pub fn payload(&self) -> &Payload {
        &self.response.request.payload
    }

    pub fn path(&self) -> &str {
        &self.args.path
    }

    pub async fn verify_execution_outcome(&self, status: TransactionStatus) -> anyhow::Result<()> {
        let execution = status.await?;
        dbg!(&execution);
        let execution = execution.into_result()?;
        let returned_resp: SignatureRequestResponse = execution.json()?;
        assert_eq!(
            returned_resp, self.response.response,
            "Returned signature request does not match"
        );
        Ok(())
    }
}

pub async fn verify_timeout(status: TransactionStatus) -> anyhow::Result<()> {
    let execution = status.await?;
    dbg!(&execution);
    assert!(execution.is_failure());
    let err = execution
        .into_result()
        .expect_err("expect execution failure");
    assert!(
        err.to_string()
            .contains(&errors::RequestError::Timeout.to_string())
    );
    Ok(())
}

#[derive(Debug)]
pub struct CKDRequestTest {
    pub response: CKDRespondArgs,
    pub args: CKDRequestArgs,
}

fn gen_ckd_derivation_path(rng: &mut impl CryptoRngCore) -> String {
    let empty: bool = rng.r#gen();
    if empty {
        "".to_string()
    } else {
        rng.r#gen::<usize>().to_string()
    }
}

impl CKDRequestTest {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        sk: &ckd::KeygenOutput,
    ) -> CKDRequestTest {
        let derivation_path = gen_ckd_derivation_path(rng);
        let app_public_key = generate_random_app_public_key(rng);
        let (request, response) = create_response_ckd(
            predecessor_id,
            &app_public_key,
            &domain_id,
            sk,
            &derivation_path,
        );
        let args = CKDRequestArgs {
            derivation_path,
            app_public_key: CKDAppPublicKey::AppPublicKey(app_public_key),
            domain_id,
        };

        CKDRequestTest {
            response: CKDRespondArgs { request, response },
            args,
        }
    }
    pub fn new_pv(
        rng: &mut impl CryptoRngCore,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        sk: &ckd::KeygenOutput,
    ) -> CKDRequestTest {
        let derivation_path = gen_ckd_derivation_path(rng);
        let (request, response) =
            create_response_ckd_pv(rng, predecessor_id, &domain_id, sk, &derivation_path);
        let args = CKDRequestArgs {
            derivation_path,
            app_public_key: request.app_public_key.clone(),
            domain_id,
        };

        CKDRequestTest {
            response: CKDRespondArgs { request, response },
            args,
        }
    }

    pub fn request_json_args(&self) -> serde_json::Value {
        serde_json::json!({
            "request": self.args,
        })
    }

    async fn verify_execution_outcome(&self, status: TransactionStatus) -> anyhow::Result<()> {
        let execution = status.await?;
        dbg!(&execution);
        let execution = execution.into_result()?;
        let returned_resp: CKDResponse = execution.json()?;
        assert_eq!(
            returned_resp, self.response.response,
            "Returned ckd request does not match"
        );
        Ok(())
    }
}

pub async fn submit_signature_response(
    response: &SignatureRespondArgs,
    contract: &SandboxMpcContract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    attested_account
        .call_mpc(contract.id())
        .respond(response.request.clone(), response.response.clone())
        .await?
        .into_result()?;
    Ok(())
}

pub async fn submit_ckd_response(
    response: &CKDRespondArgs,
    contract: &SandboxMpcContract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    attested_account
        .call_mpc(contract.id())
        .respond_ckd(response.request.clone(), response.response.clone())
        .await?
        .into_result()?;
    Ok(())
}

pub async fn submit_ckd_response_measure_gas(
    response: &CKDRespondArgs,
    contract: &SandboxMpcContract,
    attested_account: &Account,
) -> anyhow::Result<near_workspaces::types::Gas> {
    let respond = attested_account
        .call_mpc(contract.id())
        .respond_ckd(response.request.clone(), response.response.clone())
        .await?;
    let gas = respond.total_gas_burnt;
    respond.into_result()?;
    Ok(gas)
}

pub async fn await_request_in_contract_queue(
    pending_request: View<SandboxSelfCaller, Option<YieldIndex>>,
) -> anyhow::Result<()> {
    await_pending(DEFAULT_MAX_TIMEOUT_TX_INCLUDED, pending_request)
        .await
        .context("waiting for request to appear in queue")
}

/// Polls `pending_request` until it returns a yield index.
pub async fn await_pending(
    timeout: Duration,
    pending_request: View<SandboxSelfCaller, Option<YieldIndex>>,
) -> anyhow::Result<()> {
    let mut pending = pending_request.subscribe(POLL_INTERVAL).await;
    wait_for(&mut pending, timeout, Option::is_some).await?;
    Ok(())
}

/// Derives a confidential key following <https://github.com/near/threshold-signatures/blob/main/docs/confidential_key_derivation.md>
pub fn create_response_ckd(
    account_id: &AccountId,
    app_public_key: &dtos::Bls12381G1PublicKey,
    domain_id: &DomainId,
    key_package: &KeygenOutput<BLS12381SHA256>,
    derivation_path: &str,
) -> (CKDRequest, CKDResponse) {
    let request = CKDRequest::new(
        CKDAppPublicKey::AppPublicKey(app_public_key.clone()),
        *domain_id,
        account_id,
        derivation_path,
    );

    let app_id = derive_app_id(account_id, derivation_path);
    let app_pk: ckd::ElementG1 = app_public_key
        .try_into()
        .expect("invalid BLS12-381 G1 point");
    let msk = key_package.private_share.to_scalar();

    let big_s = hash_app_id_with_pk(&key_package.public_key, app_id.as_ref()) * msk;
    let y = ckd::Scalar::random(OsRng);
    let big_y = ckd::ElementG1::generator() * y;
    let big_c = big_s + app_pk * y;

    let response = CKDResponse {
        big_y: (&big_y).into(),
        big_c: (&big_c).into(),
    };
    (request, response)
}

fn create_response_ckd_pv(
    rng: &mut impl CryptoRngCore,
    account_id: &AccountId,
    domain_id: &DomainId,
    key_package: &KeygenOutput<BLS12381SHA256>,
    derivation_path: &str,
) -> (CKDRequest, CKDResponse) {
    let app_scalar = ckd::Scalar::random(&mut *rng);
    let app_pk1 = ckd::ElementG1::generator() * app_scalar;
    let app_pk2 = ckd::ElementG2::generator() * app_scalar;
    let app_public_key = CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
        pk1: dtos::Bls12381G1PublicKey::from(&app_pk1),
        pk2: dtos::Bls12381G2PublicKey::from(&app_pk2),
    });

    let request = CKDRequest::new(app_public_key, *domain_id, account_id, derivation_path);

    let app_id = derive_app_id(account_id, derivation_path);
    let msk = key_package.private_share.to_scalar();

    let big_s = hash_app_id_with_pk(&key_package.public_key, app_id.as_ref()) * msk;
    let y = ckd::Scalar::random(rng);
    let big_y = ckd::ElementG1::generator() * y;
    let big_c = big_s + app_pk1 * y;

    let response = CKDResponse {
        big_y: (&big_y).into(),
        big_c: (&big_c).into(),
    };
    (request, response)
}

pub async fn make_and_submit_requests(
    keys: &[DomainKey],
    contract: &SandboxMpcContract,
    worker: &Worker<Sandbox>,
    rng: &mut impl CryptoRngCore,
) -> (Vec<PendingSignRequest>, Vec<PendingCKDRequest>) {
    let mut pending_sign_requests = vec![];
    let mut pending_ckd_requests = vec![];

    const NUM_TESTS: usize = 2;

    let alice = worker.dev_create_account().await.unwrap();
    let alice_id = alice.id();
    let handle = alice.call_mpc_async(contract.id());

    for key in keys {
        for _ in 0..NUM_TESTS {
            match DomainResponseTest::new(rng, key, alice_id) {
                DomainResponseTest::Sign(inner) => {
                    let transaction = handle.sign(inner.args).await.unwrap();
                    pending_sign_requests.push(PendingSignRequest {
                        transaction,
                        response: inner.response,
                    });
                }
                DomainResponseTest::CKD(inner) => {
                    let gas = gas::request_app_private_key(&inner.args);
                    let transaction = handle
                        .request_app_private_key(inner.args)
                        .gas(gas)
                        .await
                        .unwrap();
                    pending_ckd_requests.push(PendingCKDRequest {
                        transaction,
                        ckd_response: inner.response,
                    });
                }
            }
        }
    }
    (pending_sign_requests, pending_ckd_requests)
}

pub fn create_response_secp256k1(
    domain_id: DomainId,
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &ts_ecdsa::KeygenOutput,
) -> (Payload, SignatureRequest, SignatureRequestResponse) {
    let (digest, payload) = process_message(msg);
    let tweak = derive_tweak(predecessor_id, path);
    let derived_sk = derive_secret_key_secp256k1(signing_key, &tweak);
    let signing_key =
        k256::ecdsa::SigningKey::from_bytes(&derived_sk.private_share.to_scalar().into()).unwrap();

    let (sig, recovery_id) = signing_key.try_sign_digest(digest).unwrap();

    let signature = K256Signature::from_ecdsa_recoverable(&sig, recovery_id);
    let respond_req = SignatureRequest::new(domain_id, payload.clone(), predecessor_id, path);

    (
        payload,
        respond_req,
        SignatureRequestResponse::Secp256k1(signature),
    )
}

pub fn create_response_ed25519(
    domain_id: DomainId,
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &eddsa::KeygenOutput,
) -> (Payload, SignatureRequest, SignatureRequestResponse) {
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

    let signature: [u8; 64] = derived_signing_key
        .sign(OsRng, &payload)
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let payload = Payload::Eddsa(payload.into());

    let respond_req = SignatureRequest::new(domain_id, payload.clone(), predecessor_id, path);

    let signature_response = SignatureRequestResponse::Ed25519 {
        signature: Ed25519Signature::from(signature),
    };

    (payload, respond_req, signature_response)
}

/// Process the message, creating the same hash with type of [`Digest`] and [`Payload`]
fn process_message(msg: &str) -> (impl Digest + use<>, Payload) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = Payload::from_legacy_ecdsa(bytes.into());
    (digest, payload_hash)
}

pub struct PendingSignRequest {
    pub transaction: TransactionStatus,
    pub response: SignatureRespondArgs,
}

pub struct PendingCKDRequest {
    pub transaction: TransactionStatus,
    pub ckd_response: CKDRespondArgs,
}

fn gen_ed25519_sign_test(
    rng: &mut impl Rng,
    domain_id: DomainId,
    predecessor_id: &AccountId,
    sk: &eddsa::KeygenOutput,
) -> SignRequestTest {
    let msg: String = rng.r#gen::<usize>().to_string();
    let path: String = rng.r#gen::<usize>().to_string();
    let (payload, request, response) =
        create_response_ed25519(domain_id, predecessor_id, &msg, &path, sk);
    let args = SignRequestBuilder::new()
        .with_path(path)
        .with_payload(near_mpc_sdk::sign::Payload::Eddsa(
            payload.as_eddsa().unwrap().to_vec().try_into().unwrap(),
        ))
        .with_domain_id(domain_id.0)
        .build();
    SignRequestTest {
        response: SignatureRespondArgs { request, response },
        args,
    }
}

pub fn gen_secp_256k1_sign_test(
    rng: &mut impl Rng,
    domain_id: DomainId,
    predecessor_id: &AccountId,
    sk: &ts_ecdsa::KeygenOutput,
) -> SignRequestTest {
    let msg: String = rng.r#gen::<usize>().to_string();
    let path: String = rng.r#gen::<usize>().to_string();
    let (payload, request, response) =
        create_response_secp256k1(domain_id, predecessor_id, &msg, &path, sk);

    let payload_bytes: [u8; 32] = *payload.as_ecdsa().unwrap();

    let args = SignRequestBuilder::new()
        .with_path(path)
        .with_payload(near_mpc_sdk::sign::Payload::Ecdsa(payload_bytes.into()))
        .with_domain_id(domain_id.0)
        .build();
    SignRequestTest {
        response: SignatureRespondArgs { request, response },
        args,
    }
}
