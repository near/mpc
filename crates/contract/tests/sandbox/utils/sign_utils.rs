use super::consts::DEFAULT_MAX_TIMEOUT_TX_INCLUDED;
use super::interface::{IntoContractType, IntoInterfaceType};
use super::shared_key_utils::{
    derive_secret_key_ed25519, derive_secret_key_secp256k1, generate_random_app_public_key,
    DomainKey, SharedSecretKey,
};
use contract_interface::types::{self as dtos};
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier as _;
use k256::{
    elliptic_curve::{point::DecompressPoint as _, Field as _, Group as _},
    AffinePoint, FieldBytes, Secp256k1,
};
use mpc_contract::{
    crypto_shared::{
        derive_key_secp256k1, derive_tweak, ed25519_types, k256_types,
        k256_types::SerializableAffinePoint, kdf::check_ec_signature, kdf::derive_app_id,
        CKDResponse, SerializableScalar, SignatureResponse,
    },
    errors,
    primitives::{
        ckd::{CKDRequest, CKDRequestArgs},
        domain::DomainId,
        signature::{Bytes, Payload, SignRequestArgs, SignatureRequest, YieldIndex},
    },
};
use near_account_id::AccountId;
use near_workspaces::{
    network::Sandbox, operations::TransactionStatus, types::NearToken, Account, Contract, Worker,
};
use rand::{rngs::OsRng, Rng};
use rand_core::CryptoRngCore;
use serde::Serialize;
use sha2::Sha256;
use signature::DigestSigner;
use std::time::Duration;
use threshold_signatures::{
    confidential_key_derivation::{self as ckd, hash_app_id_with_pk, BLS12381SHA256},
    ecdsa as ts_ecdsa,
    frost::eddsa,
    frost_ed25519::{self},
    KeygenOutput,
};

#[derive(Debug)]
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
        contract: &Contract,
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
        contract: &Contract,
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
        contract: &Contract,
    ) -> anyhow::Result<TransactionStatus> {
        match self {
            Self::Sign(inner) => {
                let status = submit_sign_request(account, &inner.args, contract).await?;
                await_request_in_contract_queue(contract, &inner.response.request, None).await?;
                Ok(status)
            }
            Self::CKD(inner) => {
                let status = submit_ckd_request(account, &inner.args, contract).await?;
                await_request_in_contract_queue(contract, &inner.response.request, None).await?;
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
    pub response: SignResponseArgs,
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
        let returned_resp: SignatureResponse = execution.json()?;
        assert_eq!(
            returned_resp, self.response.response,
            "Returned signature request does not match"
        );
        Ok(())
    }

    pub async fn submit_response(
        &self,
        contract: &Contract,
        attested_account: &Account,
    ) -> anyhow::Result<()> {
        submit_signature_response(&self.response, contract, attested_account).await
    }
}

#[derive(Debug, Serialize)]
pub struct SignResponseArgs {
    pub request: SignatureRequest,
    pub response: SignatureResponse,
}

impl SignResponseArgs {
    pub fn json_args(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }
}

pub async fn verify_timeout(status: TransactionStatus) -> anyhow::Result<()> {
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

#[derive(Debug)]
pub struct CKDRequestTest {
    pub response: CKDResponseArgs,
    pub args: CKDRequestArgs,
}

fn gen_ckd_derivation_path(rng: &mut impl CryptoRngCore) -> String {
    let empty: bool = rng.gen();
    if empty {
        "".to_string()
    } else {
        rng.gen::<usize>().to_string()
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
            app_public_key.clone(),
            &domain_id,
            sk,
            &derivation_path,
        );
        let args = CKDRequestArgs {
            derivation_path,
            app_public_key,
            domain_id,
        };

        CKDRequestTest {
            response: CKDResponseArgs { request, response },
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

#[derive(Debug, Serialize)]
pub struct CKDResponseArgs {
    pub request: CKDRequest,
    pub response: CKDResponse,
}

async fn submit_request(
    account: &Account,
    contract: &Contract,
    method: &str,
    args: impl Serialize,
) -> anyhow::Result<TransactionStatus> {
    let status = account
        .call(contract.id(), method)
        .args_json(serde_json::json!({ "request": args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    Ok(status)
}

async fn submit_sign_request(
    account: &Account,
    request: &SignRequestArgs,
    contract: &Contract,
) -> anyhow::Result<TransactionStatus> {
    submit_request(
        account,
        contract,
        contract_interface::method_names::SIGN,
        request,
    )
    .await
}

async fn submit_ckd_request(
    account: &Account,
    request: &CKDRequestArgs,
    contract: &Contract,
) -> anyhow::Result<TransactionStatus> {
    submit_request(
        account,
        contract,
        contract_interface::method_names::REQUEST_APP_PRIVATE_KEY,
        request,
    )
    .await
}

async fn submit_response(
    contract: &Contract,
    attested_account: &Account,
    method: &str,
    args: impl Serialize,
) -> anyhow::Result<()> {
    let respond = attested_account
        .call(contract.id(), method)
        .args_json(args)
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    respond.into_result()?;
    Ok(())
}

pub async fn submit_signature_response(
    response: &SignResponseArgs,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    submit_response(
        contract,
        attested_account,
        contract_interface::method_names::RESPOND,
        response,
    )
    .await
}

pub async fn submit_ckd_response(
    response: &CKDResponseArgs,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    submit_response(
        contract,
        attested_account,
        contract_interface::method_names::RESPOND_CKD,
        response,
    )
    .await
}

trait ContractQueueRequest: serde::Serialize + Sync {
    async fn is_in_queue(&self, contract: &Contract) -> Option<YieldIndex>;
}

impl ContractQueueRequest for CKDRequest {
    async fn is_in_queue(&self, contract: &Contract) -> Option<YieldIndex> {
        contract
            .view(contract_interface::method_names::GET_PENDING_CKD_REQUEST)
            .args_json(serde_json::json!({ "request": self }))
            .await
            .unwrap()
            .json()
            .unwrap()
    }
}

impl ContractQueueRequest for SignatureRequest {
    async fn is_in_queue(&self, contract: &Contract) -> Option<YieldIndex> {
        contract
            .view(contract_interface::method_names::GET_PENDING_REQUEST)
            .args_json(serde_json::json!({ "request": self }))
            .await
            .unwrap()
            .json()
            .unwrap()
    }
}

async fn await_request_in_contract_queue<T: ContractQueueRequest>(
    contract: &Contract,
    request: &T,
    max_timeout: Option<Duration>,
) -> anyhow::Result<()> {
    let timeout = max_timeout.unwrap_or(DEFAULT_MAX_TIMEOUT_TX_INCLUDED);
    let start = std::time::Instant::now();

    loop {
        if request.is_in_queue(contract).await.is_some() {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for request to appear in queue");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Derives a confidential key following https://github.com/near/threshold-signatures/blob/main/docs/confidential_key_derivation.md
fn create_response_ckd(
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

pub async fn make_and_submit_requests(
    keys: &[DomainKey],
    contract: &Contract,
    worker: &Worker<Sandbox>,
    rng: &mut impl CryptoRngCore,
) -> (Vec<PendingSignRequest>, Vec<PendingCKDRequest>) {
    let mut pending_sign_requests = vec![];
    let mut pending_ckd_requests = vec![];

    const NUM_TESTS: usize = 2;

    let alice = worker.dev_create_account().await.unwrap();
    let alice_id = alice.id();

    for key in keys {
        for _ in 0..NUM_TESTS {
            match DomainResponseTest::new(rng, key, alice_id) {
                DomainResponseTest::Sign(inner) => {
                    let transaction = submit_sign_request(&alice, &inner.args, contract)
                        .await
                        .unwrap();
                    pending_sign_requests.push(PendingSignRequest {
                        transaction,
                        response: inner.response,
                    });
                }
                DomainResponseTest::CKD(inner) => {
                    let transaction = submit_ckd_request(&alice, &inner.args, contract)
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

fn create_response_secp256k1(
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

fn create_response_ed25519(
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
fn process_message(msg: &str) -> (impl Digest, Payload) {
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
    pub ckd_response: CKDResponseArgs,
}

fn gen_ed25519_sign_test(
    rng: &mut impl Rng,
    domain_id: DomainId,
    predecessor_id: &AccountId,
    sk: &eddsa::KeygenOutput,
) -> SignRequestTest {
    let msg: String = rng.gen::<usize>().to_string();
    let path: String = rng.gen::<usize>().to_string();
    let (payload, request, response) =
        create_response_ed25519(domain_id, predecessor_id, &msg, &path, sk);
    let args = SignRequestArgs {
        payload_v2: Some(payload.clone()),
        path,
        domain_id: Some(domain_id),
        ..Default::default()
    };
    SignRequestTest {
        response: SignResponseArgs { request, response },
        args,
    }
}

pub fn gen_secp_256k1_sign_test(
    rng: &mut impl Rng,
    domain_id: DomainId,
    predecessor_id: &AccountId,
    sk: &ts_ecdsa::KeygenOutput,
) -> SignRequestTest {
    let msg: String = rng.gen::<usize>().to_string();
    let path: String = rng.gen::<usize>().to_string();
    let (payload, request, response) =
        create_response_secp256k1(domain_id, predecessor_id, &msg, &path, sk);
    let args = SignRequestArgs {
        payload_v2: Some(payload.clone()),
        path,
        domain_id: Some(domain_id),
        ..Default::default()
    };
    SignRequestTest {
        response: SignResponseArgs { request, response },
        args,
    }
}
