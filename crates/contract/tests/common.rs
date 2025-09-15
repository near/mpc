use attestation::attestation::Attestation;
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier;
use fs2::FileExt;
use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXof, GroupDigest},
        point::DecompressPoint as _,
        scalar::FromUintUnchecked,
        sec1::ToEncodedPoint,
        PrimeField,
    },
    AffinePoint, FieldBytes, ProjectivePoint, Scalar, Secp256k1,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::{
        derive_key_secp256k1, derive_tweak, ed25519_types, k256_types, kdf::check_ec_signature,
        near_public_key_to_affine_point, CKDResponse, SerializableScalar, SignatureResponse,
    },
    primitives::{
        ckd::{CKDRequest, CKDRequestArgs},
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        signature::{Bytes, SignatureRequest, Tweak},
        test_utils::bogus_ed25519_near_public_key,
        thresholds::{Threshold, ThresholdParameters},
    },
    tee::tee_state::NodeUid,
    update::UpdateId,
};
use mpc_contract::{
    crypto_shared::k256_types::SerializableAffinePoint,
    primitives::signature::{Payload, SignRequestArgs},
};
use near_sdk::{log, CurveType, PublicKey};
use near_workspaces::{
    network::Sandbox,
    result::ExecutionFinalResult,
    types::{AccountId, NearToken},
    Account, Contract, Worker,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::DigestSigner;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    process::Command,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use threshold_signatures::{
    eddsa::KeygenOutput,
    frost_secp256k1::{Ciphersuite, Secp256K1Sha256},
};
use threshold_signatures::{
    frost_ed25519,
    frost_ed25519::{keys::SigningShare, Ed25519Group, Group, VerifyingKey},
};

pub const CONTRACT_FILE_PATH: &str =
    "../../target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm";
pub const PARTICIPANT_LEN: usize = 3;

pub fn candidates(names: Option<Vec<AccountId>>) -> Participants {
    let mut participants: Participants = Participants::new();
    let names = names.unwrap_or_else(|| {
        vec![
            "alice.near".parse().unwrap(),
            "bob.near".parse().unwrap(),
            "caesar.near".parse().unwrap(),
        ]
    });

    for account_id in names {
        let _ = participants.insert(
            account_id.clone(),
            ParticipantInfo {
                url: "127.0.0.1".into(),
                sign_pk: bogus_ed25519_near_public_key(),
            },
        );
    }
    participants
}

/// Create `amount` accounts and return them along with the candidate info.
pub async fn gen_accounts(worker: &Worker<Sandbox>, amount: usize) -> (Vec<Account>, Participants) {
    let mut accounts = Vec::with_capacity(amount);
    for _ in 0..amount {
        log!("attempting to create account");
        let account = worker.dev_create_account().await.unwrap();
        log!("created account");
        accounts.push(account);
    }
    let candidates = candidates(Some(accounts.iter().map(|a| a.id().clone()).collect()));
    (accounts, candidates)
}

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize)]
struct BuildLock {
    timestamp: u64,
}

impl BuildLock {
    fn new() -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// checks if self is younger than 3 seconds
    fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > 4
    }
}

pub fn current_contract() -> &'static Vec<u8> {
    CONTRACT.get_or_init(|| {
        // Points to `/crates`
        let pkg_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        // pointing to repository root directory.
        let project_dir = pkg_dir.join("../..");
        let wasm_path =
            project_dir.join("target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm");

        let lock_path = project_dir.join(".contract.itest.build.lock");
        let mut lockfile = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("Failed to open lockfile");
        lockfile
            .lock_exclusive()
            .expect("Failed to lock build file");

        // check if we need to re-build
        let do_build = match lockfile.metadata().unwrap().len() {
            0 => true,
            _ => {
                let mut buf = String::new();
                lockfile.read_to_string(&mut buf).unwrap();
                match serde_json::from_str::<BuildLock>(&buf) {
                    Ok(build_lock) => build_lock.expired(),
                    _ => true,
                }
            }
        };

        if do_build {
            let status = Command::new("cargo")
                .args([
                    "build",
                    "--package=mpc-contract",
                    "--profile=release-contract",
                    "--target=wasm32-unknown-unknown",
                ])
                .current_dir(&project_dir)
                .status()
                .expect("Failed to run cargo build");

            assert!(status.success(), "cargo build failed");

            let status = Command::new("wasm-opt")
                .args([
                    "--enable-bulk-memory",
                    "-Oz",
                    "-o",
                    wasm_path.to_str().unwrap(),
                    wasm_path.to_str().unwrap(),
                ])
                .current_dir(project_dir)
                .status()
                .expect("Failed to run wasm-opt");

            assert!(status.success(), "wasm-opt failed");
            lockfile.set_len(0).unwrap();
            lockfile
                .write_all(serde_json::to_string(&BuildLock::new()).unwrap().as_bytes())
                .expect("Failed to write timestamp to lockfile");
        }
        std::fs::read(CONTRACT_FILE_PATH).unwrap()
    })
}

pub async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = &current_contract();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    (worker, contract)
}

/// Initializes the contract with `pks` as public keys, a set of participants and a threshold.
pub async fn init_with_candidates(
    pks: Vec<near_sdk::PublicKey>,
) -> (Worker<Sandbox>, Contract, Vec<Account>) {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, PARTICIPANT_LEN).await;
    let threshold_parameters = {
        let threshold = Threshold::new(((participants.len() as f64) * 0.6).ceil() as u64);
        ThresholdParameters::new(participants, threshold).unwrap()
    };

    let call_builder = if !pks.is_empty() {
        let (domains, keys): (Vec<_>, Vec<_>) = pks
            .into_iter()
            .enumerate()
            .map(|(i, pk)| {
                let domain_id = DomainId((i as u64) * 2);
                let scheme = match pk.curve_type() {
                    CurveType::ED25519 => SignatureScheme::Ed25519,
                    CurveType::SECP256K1 => SignatureScheme::Secp256k1,
                };
                let key = pk.try_into().unwrap();

                (
                    DomainConfig {
                        id: domain_id,
                        scheme,
                    },
                    KeyForDomain {
                        attempt: AttemptId::new(),
                        domain_id,
                        key,
                    },
                )
            })
            .unzip();

        contract.call("init_running").args_json(serde_json::json!({
            "domains": domains,
            "next_domain_id": (domains.len() as u64) * 2,
            "keyset": Keyset::new(EpochId::new(5), keys),
            "parameters": threshold_parameters,
        }))
    } else {
        contract.call("init").args_json(serde_json::json!({
            "parameters": threshold_parameters,
            "init_config": None::<InitConfig>,
        }))
    };

    let init = call_builder
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();
    dbg!(init);
    (worker, contract, accounts)
}

pub enum SharedSecretKey {
    Secp256k1(k256::elliptic_curve::SecretKey<k256::Secp256k1>),
    Ed25519(KeygenOutput),
}

pub fn new_secp256k1() -> (
    near_sdk::PublicKey,
    k256::elliptic_curve::SecretKey<k256::Secp256k1>,
) {
    let secret_key = k256::SecretKey::random(&mut rand::thread_rng());
    let public_key = secret_key.public_key();

    let compressed_key = public_key.as_affine().to_encoded_point(false).as_bytes()[1..65].to_vec();

    let public_key = near_sdk::PublicKey::from_parts(CurveType::SECP256K1, compressed_key).unwrap();

    (public_key, secret_key)
}

pub async fn init_env_secp256k1(
    num_domains: usize,
) -> (
    Worker<Sandbox>,
    Contract,
    Vec<Account>,
    Vec<SharedSecretKey>,
) {
    let (public_keys, secret_keys) =
        make_key_for_domains(vec![SignatureScheme::Secp256k1; num_domains]);
    let (worker, contract, accounts) = init_with_candidates(public_keys).await;

    (worker, contract, accounts, secret_keys)
}

pub fn make_key_for_domains(
    protocols: Vec<SignatureScheme>,
) -> (Vec<near_sdk::PublicKey>, Vec<SharedSecretKey>) {
    protocols
        .into_iter()
        .map(|protocol| match protocol {
            SignatureScheme::Secp256k1 | SignatureScheme::CkdSecp256k1 => {
                let (pk, sk) = new_secp256k1();
                (pk, SharedSecretKey::Secp256k1(sk))
            }
            SignatureScheme::Ed25519 => {
                let (pk, sk) = new_ed25519();
                (pk, SharedSecretKey::Ed25519(sk))
            }
        })
        .unzip()
}

pub fn new_ed25519() -> (near_sdk::PublicKey, KeygenOutput) {
    let scalar = curve25519_dalek::Scalar::random(&mut OsRng);
    let private_share = SigningShare::new(scalar);
    let public_key_element = Ed25519Group::generator() * scalar;
    let public_key = VerifyingKey::new(public_key_element);

    let keygen_output = KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().compress().as_bytes().to_vec();
    let pk = near_sdk::PublicKey::from_parts(CurveType::ED25519, compressed_key).unwrap();

    (pk, keygen_output)
}

pub async fn init_env_ed25519(
    num_domains: usize,
) -> (
    Worker<Sandbox>,
    Contract,
    Vec<Account>,
    Vec<SharedSecretKey>,
) {
    let (public_keys, secret_keys) =
        make_key_for_domains(vec![SignatureScheme::Ed25519; num_domains]);
    let (worker, contract, accounts) = init_with_candidates(public_keys).await;

    (worker, contract, accounts, secret_keys)
}

/// Process the message, creating the same hash with type of [`Digest`] and [`Payload`]
pub fn process_message(msg: &str) -> (impl Digest, Payload) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = Payload::from_legacy_ecdsa(bytes.into());
    (digest, payload_hash)
}

pub fn derive_secret_key_secp256k1(secret_key: &k256::SecretKey, tweak: &Tweak) -> k256::SecretKey {
    let tweak = Scalar::from_repr(tweak.as_bytes().into()).unwrap();
    k256::SecretKey::new((tweak + secret_key.to_nonzero_scalar().as_ref()).into())
}

pub fn derive_secret_key_ed25519(secret_key: &KeygenOutput, tweak: &Tweak) -> KeygenOutput {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    let private_share = SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key =
        VerifyingKey::new(secret_key.public_key.to_element() + Ed25519Group::generator() * tweak);

    KeygenOutput {
        private_share,
        public_key,
    }
}

pub async fn create_response(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &SharedSecretKey,
) -> (Payload, SignatureRequest, SignatureResponse) {
    match sk {
        SharedSecretKey::Secp256k1(sk) => create_response_secp256k1(predecessor_id, msg, path, sk),
        SharedSecretKey::Ed25519(sk) => create_response_ed25519(predecessor_id, msg, path, sk),
    }
}

pub fn create_response_secp256k1(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &k256::SecretKey,
) -> (Payload, SignatureRequest, SignatureResponse) {
    let (digest, payload) = process_message(msg);
    let pk = sk.public_key();

    let tweak = derive_tweak(predecessor_id, path);
    let derived_sk = derive_secret_key_secp256k1(sk, &tweak);
    let derived_pk = derive_key_secp256k1(&pk.into(), &tweak).unwrap();
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let respond_req = SignatureRequest::new(DomainId(0), payload.clone(), predecessor_id, path);
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
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &KeygenOutput,
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

    let respond_req = SignatureRequest::new(DomainId(0), payload.clone(), predecessor_id, path);

    let signature_response = SignatureResponse::Ed25519 {
        signature: ed25519_types::Signature::new(signature),
    };

    (payload, respond_req, signature_response)
}

pub async fn sign_and_validate(
    request: &SignRequestArgs,
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

pub fn example_secp256k1_point() -> PublicKey {
    "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd".parse().unwrap()
}

// based on https://github.com/near/threshold-signatures/blob/eb04be447bc3385000a71adfcfc930e44819bff1/src/confidential_key_derivation/ckd.rs
fn hash2curve(app_id: &[u8]) -> ProjectivePoint {
    const DOMAIN: &[u8] = b"NEAR CURVE_XOF:SHAKE-256_SSWU_RO_";
    <Secp256k1 as GroupDigest>::hash_from_bytes::<ExpandMsgXof<sha3::Shake256>>(
        &[app_id],
        &[DOMAIN],
    )
    .unwrap()
}

/// Derives a confidential key following https://github.com/near/threshold-signatures/blob/main/docs/confidential_key_derivation.md
pub fn create_response_ckd(
    account_id: &AccountId,
    app_public_key: near_sdk::PublicKey,
    domain_id: &DomainId,
    signing_key: &ecdsa::elliptic_curve::SecretKey<k256::Secp256k1>,
) -> (CKDRequest, CKDResponse) {
    let request = CKDRequest::new(app_public_key.clone(), account_id.clone(), *domain_id);

    let app_id = account_id.as_bytes();
    let app_pk = near_public_key_to_affine_point(app_public_key);
    let msk = k256::Scalar::from_uint_unchecked(signing_key.as_scalar_primitive().to_uint());
    let big_s = hash2curve(app_id) * msk;
    let (y, big_y) = Secp256K1Sha256::generate_nonce(&mut OsRng);
    let big_c = big_s + app_pk * y;

    let response = CKDResponse {
        big_y: SerializableAffinePoint {
            affine_point: big_y.to_affine(),
        },
        big_c: SerializableAffinePoint {
            affine_point: big_c.to_affine(),
        },
    };
    (request, response)
}

pub async fn derive_confidential_key_and_validate(
    account: Account,
    request: &CKDRequestArgs,
    respond: Option<(&CKDRequest, &CKDResponse)>,
    contract: &Contract,
) -> anyhow::Result<()> {
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
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if let Some((respond_req, respond_resp)) = respond {
        assert!(account.id() == &respond_req.app_id);
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

pub async fn vote_update_till_completion(
    contract: &Contract,
    accounts: &[Account],
    proposal_id: &UpdateId,
) {
    for voter in accounts {
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({
                "id": proposal_id,
            }))
            .max_gas()
            .transact()
            .await
            .unwrap();

        dbg!(&execution);

        let update_occurred: bool = execution.json().expect("Vote cast was unsuccessful");

        if update_occurred {
            return;
        }
    }
    panic!("Update didn't occurred")
}

pub fn check_call_success(result: ExecutionFinalResult) {
    assert!(
        result.is_success(),
        "execution should have succeeded: {result:#?}"
    );
}

/// Helper function to get TEE participants from contract.
pub async fn get_tee_accounts(contract: &Contract) -> anyhow::Result<Vec<NodeUid>> {
    Ok(contract
        .call("get_tee_accounts")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json()?)
}

/// Helper function to submit participant info with TEE attestation.
pub async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &PublicKey,
) -> anyhow::Result<bool> {
    let result = account
        .call(contract.id(), "submit_participant_info")
        .args_borsh((attestation.clone(), tls_key.clone()))
        .max_gas()
        .transact()
        .await?;
    Ok(result.is_success())
}
