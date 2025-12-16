// TODO(#1657): split this file
use assert_matches::assert_matches;
use contract_interface::types::{
    self as dtos, Attestation, Bls12381G1PublicKey, Ed25519PublicKey, MockAttestation,
};
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier as _;
use elliptic_curve::{Field as _, Group as _};
use fs2::FileExt;
use k256::{
    elliptic_curve::{point::DecompressPoint as _, sec1::ToEncodedPoint as _, PrimeField as _},
    AffinePoint, FieldBytes, Secp256k1,
};
use mpc_contract::{
    crypto_shared::{
        derive_key_secp256k1, derive_tweak, ed25519_types, k256_types, kdf::check_ec_signature,
        types::PublicKeyExtended, CKDResponse, SerializableScalar, SignatureResponse,
    },
    primitives::{
        ckd::{CKDRequest, CKDRequestArgs},
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyEventId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        signature::{Bytes, SignatureRequest, Tweak},
        test_utils::bogus_ed25519_near_public_key,
        thresholds::{Threshold, ThresholdParameters},
    },
    tee::tee_state::NodeId,
    update::{ProposeUpdateArgs, UpdateId},
};
use mpc_contract::{
    crypto_shared::{k256_types::SerializableAffinePoint, kdf::derive_app_id},
    primitives::signature::{Payload, SignRequestArgs},
    state::ProtocolContractState,
};
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::Gas;

use super::initializing_utils::{vote_add_domains, vote_public_key};
use crate::sandbox::initializing_utils::start_keygen_instance;
use near_account_id::AccountId;
use near_workspaces::{
    network::Sandbox, operations::TransactionStatus, result::ExecutionFinalResult,
    types::NearToken, Account, Contract, Worker,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use signature::DigestSigner;
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    process::Command,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use threshold_signatures::{
    blstrs,
    confidential_key_derivation::{self as ckd, hash_app_id_with_pk, BLS12381SHA256},
    ecdsa as ts_ecdsa, eddsa,
    frost_ed25519::{self, keys::SigningShare, Ed25519Group, Group as _, VerifyingKey},
    frost_secp256k1::{self, Secp256K1Group},
    KeygenOutput,
};
use utilities::AccountIdExtV1;

pub const PARTICIPANT_LEN: usize = 10;
const CURRENT_CONTRACT_PACKAGE_NAME: &str = "mpc-contract";
const DUMMY_MIGRATION_CONTRACT_PACKAGE_NAME: &str = "test-migration-contract";

/// Convenience constant used only in tests. The contract itself does not require a specific
/// gas attachment; in practice, nodes usually attach the maximum available gas. For testing,
/// we use this constant to attach a fixed amount to each call and detect if gas usage
/// increases unexpectedly in the future.
///
/// TODO(#926) this gas was bumped from 22 to 34 in https://github.com/near/mpc/pull/1559. This
/// might be due to the high cost of `self.protocol_state = new_state` in the vote_reshard
/// contract call. This needs to be investigated to understand why the increase was necessary.
pub const GAS_FOR_VOTE_RESHARED: Gas = Gas::from_tgas(34);
pub const GAS_FOR_VOTE_PK: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_CANCEL_KEYGEN: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_CANCEL_RESHARING: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_NEW_DOMAIN: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_NEW_PARAMETERS: Gas = Gas::from_tgas(22);
/// TODO(#1571): Gas cost for voting on contract updates. Reduced somewhat after
/// optimization (#1617) by avoiding full contract code deserialization; there’s likely still
/// room for further optimization.
pub const GAS_FOR_VOTE_UPDATE: Gas = Gas::from_tgas(232);
/// Gas required for votes cast before the threshold is reached (votes 1 through N-1).
/// These votes are cheap because they only record the vote without triggering the actual
/// contract update deployment and migration.
pub const GAS_FOR_VOTE_BEFORE_THRESHOLD: Gas = Gas::from_tgas(4);
/// Maximum gas expected for the threshold vote that triggers the contract update.
/// This vote is more expensive because it deploys the new contract code and executes
/// the migration function.
pub const MAX_GAS_FOR_THRESHOLD_VOTE: Gas = Gas::from_tgas(147);

/// This is the current deposit required for a contract deploy. This is subject to change but make
/// sure that it's not larger than 2mb. We can go up to 4mb technically but our contract should
/// not be getting that big.
///
/// TODO(#771): Reduce this to the minimal value possible after #770 is resolved
pub const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(13000);

pub const ALL_SIGNATURE_SCHEMES: &[SignatureScheme; 4] = &[
    SignatureScheme::Secp256k1,
    SignatureScheme::Ed25519,
    SignatureScheme::Bls12381,
    SignatureScheme::V2Secp256k1,
];

pub fn gen_participant_info() -> ParticipantInfo {
    ParticipantInfo {
        url: "127.0.0.1".into(),
        sign_pk: bogus_ed25519_near_public_key(),
    }
}

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
        let _ = participants.insert(account_id.clone(), gen_participant_info());
    }
    participants
}

pub async fn gen_account(worker: &Worker<Sandbox>) -> (Account, AccountId) {
    let account = worker.dev_create_account().await.unwrap();
    let id = account.id().as_v2_account_id();
    (account, id)
}

/// Create `amount` accounts and return them along with the candidate info.
pub async fn gen_accounts(worker: &Worker<Sandbox>, amount: usize) -> (Vec<Account>, Participants) {
    let mut accounts = Vec::with_capacity(amount);
    let mut account_ids = Vec::with_capacity(amount);
    for _ in 0..amount {
        let (account, account_id) = gen_account(worker).await;
        accounts.push(account);
        account_ids.push(account_id);
    }
    let candidates = candidates(Some(account_ids));
    (accounts, candidates)
}

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

    /// checks if self is older than 4 seconds
    fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > 4
    }
}

/// Generic contract builder
fn load_contract(package_name: &str) -> Vec<u8> {
    let lockfile_name = format!("{package_name}.itest.build.lock");

    // Points to `/crates`
    let pkg_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // pointing to repository root directory.
    let project_dir = pkg_dir.join("../..");

    let artifact_name = format!("{package_name}.wasm").replace('-', "_");
    let wasm_path = project_dir.join(format!(
        "target/wasm32-unknown-unknown/release-contract/{artifact_name}"
    ));

    let lock_path = project_dir.join(lockfile_name);
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
                &format!("--package={package_name}"),
                "--profile=release-contract",
                "--target=wasm32-unknown-unknown",
                "--locked",
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
            .current_dir(&project_dir)
            .status()
            .expect("Failed to run wasm-opt");

        assert!(status.success(), "wasm-opt failed");

        lockfile.set_len(0).unwrap();
        lockfile
            .write_all(serde_json::to_string(&BuildLock::new()).unwrap().as_bytes())
            .expect("Failed to write timestamp to lockfile");
    }

    std::fs::read(wasm_path).unwrap()
}

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static MIGRATION_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

pub fn current_contract() -> &'static [u8] {
    CONTRACT.get_or_init(|| load_contract(CURRENT_CONTRACT_PACKAGE_NAME))
}

pub fn migration_contract() -> &'static [u8] {
    MIGRATION_CONTRACT.get_or_init(|| load_contract(DUMMY_MIGRATION_CONTRACT_PACKAGE_NAME))
}

pub async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = &current_contract();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    (worker, contract)
}

pub struct DomainPublicKey {
    public_key: PublicKeyExtended,
    config: DomainConfig,
}

/// Initializes the contract with `pks` as public keys, a set of participants and a threshold.
pub async fn init_with_candidates(
    pks: Vec<dtos::PublicKey>,
    init_config: Option<dtos::InitConfig>,
    number_of_participants: usize,
) -> (
    Worker<Sandbox>,
    Contract,
    Vec<Account>,
    Vec<DomainPublicKey>,
) {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, number_of_participants).await;
    let threshold_parameters = {
        let threshold = Threshold::new(((participants.len() as f64) * 0.6).ceil() as u64);
        ThresholdParameters::new(participants.clone(), threshold).unwrap()
    };
    let mut ret_domains: Vec<DomainPublicKey> = Vec::new();

    let call_builder = if !pks.is_empty() {
        let (domains, keys): (Vec<_>, Vec<_>) = pks
            .into_iter()
            .enumerate()
            .map(|(i, pk)| {
                let domain_id = DomainId((i as u64) * 2);
                let scheme = match pk {
                    dtos::PublicKey::Ed25519(_) => SignatureScheme::Ed25519,
                    dtos::PublicKey::Secp256k1(_) => SignatureScheme::Secp256k1,
                    dtos::PublicKey::Bls12381(_) => SignatureScheme::Bls12381,
                };
                let key: PublicKeyExtended = pk.try_into().unwrap();
                ret_domains.push(DomainPublicKey {
                    public_key: key.clone(),
                    config: DomainConfig {
                        id: domain_id,
                        scheme,
                    },
                });
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
            "init_config": init_config,
        }))
    };

    let init = call_builder
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    // Give each participant a valid attestation initially
    for ((_, _, participant), account) in participants.participants().iter().zip(&accounts) {
        let tee_submission_result = submit_participant_info(
            account,
            &contract,
            &Attestation::Mock(MockAttestation::Valid),
            &participant.sign_pk.into_interface_type(),
        )
        .await;

        assert_matches!(
            tee_submission_result,
            Ok(true),
            "`submit_participant_info` must succeed for mock attestations"
        );
    }
    dbg!(init);
    (worker, contract, accounts, ret_domains)
}

#[derive(Debug, Clone)]
pub enum SharedSecretKey {
    Secp256k1(ts_ecdsa::KeygenOutput),
    Ed25519(eddsa::KeygenOutput),
    Bls12381(ckd::KeygenOutput),
}

pub fn new_secp256k1() -> (dtos::PublicKey, ts_ecdsa::KeygenOutput) {
    let scalar = k256::Scalar::random(&mut rand::thread_rng());
    let private_share = frost_secp256k1::keys::SigningShare::new(scalar);
    let public_key_element = Secp256K1Group::generator() * scalar;
    let public_key = frost_secp256k1::VerifyingKey::new(public_key_element);

    let keygen_output = ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_encoded_point(false);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&compressed_key.as_bytes()[1..]);
    let pk = dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey::from(bytes));

    (pk, keygen_output)
}

pub fn make_key_for_domain(domain_scheme: SignatureScheme) -> (dtos::PublicKey, SharedSecretKey) {
    match domain_scheme {
        SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
            let (pk, sk) = new_secp256k1();
            (pk, SharedSecretKey::Secp256k1(sk))
        }
        SignatureScheme::Ed25519 => {
            let (pk, sk) = new_ed25519();
            (pk, SharedSecretKey::Ed25519(sk))
        }
        SignatureScheme::Bls12381 => {
            let (pk, sk) = new_bls12381();
            (pk, SharedSecretKey::Bls12381(sk))
        }
    }
}

pub fn new_ed25519() -> (dtos::PublicKey, eddsa::KeygenOutput) {
    let scalar = curve25519_dalek::Scalar::random(&mut OsRng);
    let private_share = SigningShare::new(scalar);
    let public_key_element = Ed25519Group::generator() * scalar;
    let public_key = VerifyingKey::new(public_key_element);

    let keygen_output = eddsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().compress().as_bytes().to_vec();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&compressed_key);
    let pk = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey::from(bytes));

    (pk, keygen_output)
}

pub fn new_bls12381() -> (dtos::PublicKey, ckd::KeygenOutput) {
    let scalar = ckd::Scalar::random(&mut OsRng);
    let private_share = ckd::SigningShare::new(scalar);
    let public_key_element = ckd::ElementG2::generator() * scalar;
    let public_key = ckd::VerifyingKey::new(public_key_element);

    let keygen_output = ckd::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_compressed();
    let pk = dtos::PublicKey::from(dtos::Bls12381G2PublicKey::from(compressed_key));

    (pk, keygen_output)
}

#[derive(Debug, Clone)]
pub struct DomainKey {
    pub domain_config: DomainConfig,
    pub domain_secret_key: SharedSecretKey,
    pub domain_public_key: PublicKeyExtended,
}

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

pub struct SignRequestSetup {
    pub response: SignResponseArgs,
    pub args: SignRequestArgs,
}

impl SignRequestSetup {
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
}

impl DomainKey {
    pub fn domain_id(&self) -> DomainId {
        self.domain_config.id
    }
    pub fn create_sign_request(
        &self,
        predecessor_id: &AccountId,
        msg: &str,
        path: &str,
    ) -> SignRequestSetup {
        let domain_id = self.domain_config.id;
        let (payload, request, response) = match &self.domain_secret_key {
            SharedSecretKey::Secp256k1(sk) => {
                create_response_secp256k1(domain_id, predecessor_id, msg, path, sk)
            }
            SharedSecretKey::Ed25519(sk) => {
                create_response_ed25519(domain_id, predecessor_id, msg, path, sk)
            }
            SharedSecretKey::Bls12381(_) => unreachable!(),
        };
        let args = SignRequestArgs {
            payload_v2: Some(payload.clone()),
            path: path.into(),
            domain_id: Some(self.domain_id()),
            ..Default::default()
        };
        SignRequestSetup {
            response: SignResponseArgs { request, response },
            args,
        }
    }
}

pub struct ContractSetup {
    pub worker: Worker<Sandbox>,
    pub contract: Contract,
    pub mpc_signer_accounts: Vec<Account>,
    pub keys: Vec<DomainKey>,
}

pub async fn init_env(schemes: &[SignatureScheme], number_of_participants: usize) -> ContractSetup {
    let (public_keys, secret_keys): (Vec<_>, Vec<_>) = schemes
        .iter()
        .map(|scheme| make_key_for_domain(*scheme))
        .collect();

    let (worker, contract, mpc_signer_accounts, domains) =
        init_with_candidates(public_keys, None, number_of_participants).await;
    let keys = domains
        .into_iter()
        .zip(secret_keys.into_iter())
        .map(|(public, secret)| DomainKey {
            domain_config: public.config,
            domain_secret_key: secret,
            domain_public_key: public.public_key,
        })
        .collect();

    ContractSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    }
}

/// Process the message, creating the same hash with type of [`Digest`] and [`Payload`]
pub fn process_message(msg: &str) -> (impl Digest, Payload) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = Payload::from_legacy_ecdsa(bytes.into());
    (digest, payload_hash)
}

pub fn derive_secret_key_secp256k1(
    secret_key: &ts_ecdsa::KeygenOutput,
    tweak: &Tweak,
) -> ts_ecdsa::KeygenOutput {
    let tweak = k256::Scalar::from_repr(tweak.as_bytes().into()).unwrap();
    let private_share =
        frost_secp256k1::keys::SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key = frost_secp256k1::VerifyingKey::new(
        secret_key.public_key.to_element() + Secp256K1Group::generator() * tweak,
    );
    ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    }
}

pub fn derive_secret_key_ed25519(
    secret_key: &eddsa::KeygenOutput,
    tweak: &Tweak,
) -> eddsa::KeygenOutput {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    let private_share = SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key =
        VerifyingKey::new(secret_key.public_key.to_element() + Ed25519Group::generator() * tweak);

    eddsa::KeygenOutput {
        private_share,
        public_key,
    }
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

pub async fn sign_and_validate(
    account: &Account,
    request: &SignRequestArgs,
    respond: Option<&SignResponseArgs>,
    contract: &Contract,
    attested_account: &Account,
) -> anyhow::Result<()> {
    let status = submit_sign_request(account, request, contract).await?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if let Some(response) = respond {
        submit_signature_response(response, contract, attested_account).await?;
    }

    let execution = status.await?;
    dbg!(&execution);
    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: SignatureResponse = execution.json()?;

    if let Some(response) = respond {
        assert_eq!(
            &returned_resp, &response.response,
            "Returned signature request does not match"
        );
    }
    Ok(())
}

pub fn generate_random_app_public_key(rng: &mut impl CryptoRngCore) -> Bls12381G1PublicKey {
    let x = blstrs::Scalar::random(rng);
    let big_x = blstrs::G1Projective::generator() * x;
    Bls12381G1PublicKey::from(big_x.to_compressed())
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

/// Upgrades the given contract to the [`current_contract`] binary.
///
/// This function:
/// 1. Submits a proposal to upgrade the contract.
/// 2. Casts votes until the proposal is executed.
/// 3. Verifies the contract was upgraded by checking the contract's binary.
///
/// Panics if:
/// - The proposal transaction fails,
/// - The state call is not deserializable,
/// - Or the post-upgrade code does not match the expected binary.
pub async fn propose_and_vote_contract_binary(
    accounts: &[Account],
    contract: &Contract,
    new_contract_binary: &[u8],
) {
    let propose_update_execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(new_contract_binary.to_vec()),
            config: None,
        })
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .expect("propose update call succeeds");

    assert!(
        propose_update_execution.is_success(),
        "propose update call failed"
    );

    let proposal_id: UpdateId = propose_update_execution.json().unwrap();

    // Try calling into state and see if it works.
    let state_request_execution = accounts[0]
        .call(contract.id(), "state")
        .transact()
        .await
        .expect("state request succeeds");

    let _state: ProtocolContractState = state_request_execution
        .json()
        .expect("state is deserializable.");

    vote_update_till_completion(contract, accounts, &proposal_id).await;

    let contract_binary_post_upgrade = contract.view_code().await.unwrap();
    assert_eq!(
        hash(new_contract_binary),
        hash(&contract_binary_post_upgrade),
        "Code hash post upgrade is not matching the proposed binary."
    );
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
            .gas(GAS_FOR_VOTE_UPDATE)
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

/// Returns an error if any of the outcomes in [`ExecutionFinalResult`] failed  
fn all_receipts_successful(result: ExecutionFinalResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.outcomes().iter().all(|o| !o.is_failure()),
        "execution should have succeeded: {result:#?}"
    );
    Ok(())
}

/// Helper function to get TEE participants from contract.
pub async fn get_tee_accounts(contract: &Contract) -> anyhow::Result<BTreeSet<NodeId>> {
    Ok(contract
        .call("get_tee_accounts")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<NodeId>>()?
        .into_iter()
        .collect())
}

/// Helper function to submit participant info with TEE attestation.
pub async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<bool> {
    let result = account
        .call(contract.id(), "submit_participant_info")
        .args_json((attestation, tls_key))
        .max_gas()
        .transact()
        .await?;
    Ok(result.is_success())
}

pub async fn get_participant_attestation(
    contract: &Contract,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<Option<Attestation>> {
    let result = contract
        .as_account()
        .call(contract.id(), "get_attestation")
        .args_json(json!({
            "tls_public_key": tls_key
        }))
        .max_gas()
        .transact()
        .await?;

    Ok(result.json()?)
}

pub async fn assert_running_return_participants(
    contract: &Contract,
) -> anyhow::Result<Participants> {
    // Verify contract is back to running state with new threshold
    let final_state: ProtocolContractState = contract.view("state").await?.json()?;
    let ProtocolContractState::Running(running_state) = final_state else {
        panic!(
            "Expected contract to be in Running state after resharing, but got: {:?}",
            final_state
        );
    };
    Ok(running_state.parameters.participants().clone())
}

pub async fn assert_running_return_threshold(contract: &Contract) -> Threshold {
    let final_state: ProtocolContractState = get_state(contract).await;
    let ProtocolContractState::Running(running_state) = final_state else {
        panic!(
            "Expected contract to be in Running state: {:?}",
            final_state
        );
    };
    running_state.parameters.threshold()
}

pub async fn submit_tee_attestations(
    contract: &Contract,
    env_accounts: &mut [Account],
    node_ids: &BTreeSet<NodeId>,
) -> anyhow::Result<()> {
    env_accounts.sort_by(|left, right| left.id().cmp(right.id()));
    for (account, node_id) in env_accounts.iter().zip(node_ids) {
        assert_eq!(
            *account.id().as_v2_account_id(),
            node_id.account_id,
            "AccountId mismatch"
        );
        let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
        let result = submit_participant_info(
            account,
            contract,
            &attestation,
            &node_id.tls_public_key.into_interface_type(),
        )
        .await?;
        assert!(result);
    }
    Ok(())
}

pub async fn get_participants(contract: &Contract) -> anyhow::Result<Participants> {
    let state = contract
        .call("state")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?;
    let value: ProtocolContractState = state.json()?;
    let ProtocolContractState::Running(running) = value else {
        panic!("Expected running state")
    };

    Ok(running.parameters.participants().clone())
}

/// This function assumes that the accounts are sorted by participant id.
/// Returns the shared_secret_key in the same order as
/// the corresponding domain configs supplied.
pub async fn call_contract_key_generation<const N: usize>(
    domains_to_add: &[DomainConfig; N],
    accounts: &[Account],
    contract: &Contract,
    expected_epoch_id: u64,
) -> [DomainKey; N] {
    let mut domain_keys = vec![];

    let existing_domains = {
        let state: ProtocolContractState = get_state(contract).await;
        match state {
            ProtocolContractState::Running(state) => state.domains.domains().len(),
            _ => panic!("ProtocolContractState must be Running"),
        }
    };

    vote_add_domains(contract, accounts, domains_to_add)
        .await
        .unwrap();

    let state: ProtocolContractState = get_state(contract).await;
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(
                state.domains.domains().len(),
                existing_domains + domains_to_add.len()
            );
        }
        _ => panic!("should be in initializing state"),
    };

    for domain in domains_to_add.iter() {
        let attempt_id = AttemptId::new();
        let key_event_id = KeyEventId {
            epoch_id: EpochId::new(expected_epoch_id),
            domain_id: domain.id,
            attempt_id,
        };
        start_keygen_instance(contract, accounts, key_event_id)
            .await
            .unwrap();
        let (public_key, shared_secret_key) = make_key_for_domain(domain.scheme);

        domain_keys.push(DomainKey {
            domain_config: domain.clone(),
            domain_secret_key: shared_secret_key,
            domain_public_key: public_key.clone().try_into().unwrap(),
        });

        vote_public_key(contract, accounts, key_event_id, public_key)
            .await
            .unwrap();
    }

    let state: ProtocolContractState = get_state(contract).await;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.get(), expected_epoch_id);
            assert_eq!(
                state.domains.domains().len(),
                domains_to_add.len() + existing_domains
            );
        }
        state => panic!("should be in running state. Actual state: {state:#?}"),
    };

    domain_keys.try_into().unwrap()
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

pub struct InjectedContractState {
    pub pending_sign_requests: Vec<PendingSignRequest>,
    pub domain_keys: Vec<DomainKey>,
}

/// Adds dummy state to a contract (threshold proposal, domains, sign requests)
/// so that migration paths are exercised in upgrade tests.
///
/// The pending signature requests can be responded to.
pub async fn execute_key_generation_and_add_random_state(
    accounts: &[Account],
    participants: Participants,
    contract: &Contract,
    worker: &Worker<Sandbox>,
    rng: &mut impl CryptoRngCore,
) -> InjectedContractState {
    const EPOCH_ID: u64 = 0;
    let threshold = assert_running_return_threshold(contract).await;

    // 1. Submit a threshold proposal (raise threshold to threshold + 1).
    let dummy_threshold_parameters =
        ThresholdParameters::new(participants, Threshold::new(threshold.value() + 1)).unwrap();
    let dummy_proposal = json!({
        "prospective_epoch_id": 1,
        "proposal": dummy_threshold_parameters,
    });
    accounts[0]
        .call(contract.id(), "vote_new_parameters")
        .args_json(dummy_proposal)
        .max_gas()
        .transact()
        .await
        .unwrap()
        .unwrap();

    // 2. Add multiple domains.
    let domains_to_add = [
        DomainConfig {
            id: 0.into(),
            scheme: SignatureScheme::Ed25519,
        },
        DomainConfig {
            id: 1.into(),
            scheme: SignatureScheme::Secp256k1,
        },
        DomainConfig {
            id: 2.into(),
            scheme: SignatureScheme::Ed25519,
        },
    ];
    let domain_keys =
        call_contract_key_generation(&domains_to_add, accounts, contract, EPOCH_ID).await;

    // 3. Submit pending sign requests.
    let (pending_sign_requests, _) =
        make_and_submit_requests(&domain_keys, contract, worker, rng).await;

    InjectedContractState {
        pending_sign_requests,
        domain_keys: domain_keys.to_vec(),
    }
}

fn generate_random_request_payloads(n: usize, rng: &mut impl CryptoRngCore) -> String {
    (0..n).map(|_| rng.sample(Alphanumeric) as char).collect()
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
                    let req = key.create_sign_request(&alice_id, message, path);
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

pub async fn vote_for_hash(
    account: &Account,
    contract: &Contract,
    image_hash: &MpcDockerImageHash,
) -> anyhow::Result<()> {
    let result = account
        .call(contract.id(), "vote_code_hash")
        .args_json(serde_json::json!({"code_hash": image_hash}))
        .transact()
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}

fn hash(code: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(code);
    hasher.finalize().into()
}

pub async fn execute_async_transactions(
    accounts: &[Account],
    contract: &Contract,
    function_name: &str,
    json_args: &impl Serialize,
    attached_gas: Gas,
) -> anyhow::Result<()> {
    let mut transactions = vec![];
    for account in accounts.iter() {
        let result = account
            .call(contract.id(), function_name)
            .gas(attached_gas)
            .args_json(json_args)
            .transact_async()
            .await?;
        transactions.push(result);
    }
    for transaction in transactions {
        let result = transaction.await?;
        all_receipts_successful(result)?;
    }
    Ok(())
}

// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore

pub(crate) trait IntoInterfaceType<InterfaceType> {
    fn into_interface_type(self) -> InterfaceType;
}

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoInterfaceType<dtos::Ed25519PublicKey> for &near_sdk::PublicKey {
    fn into_interface_type(self) -> dtos::Ed25519PublicKey {
        // This function should not be called with any other type
        assert!(self.curve_type() == near_sdk::CurveType::ED25519);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.as_bytes()[1..]);
        dtos::Ed25519PublicKey::from(bytes)
    }
}

impl IntoInterfaceType<dtos::Bls12381G1PublicKey> for &ckd::ElementG1 {
    fn into_interface_type(self) -> dtos::Bls12381G1PublicKey {
        dtos::Bls12381G1PublicKey::from(self.to_compressed())
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::Ed25519PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, self.0.into()).unwrap()
    }
}

impl IntoContractType<ckd::ElementG1> for &dtos::Bls12381G1PublicKey {
    fn into_contract_type(self) -> ckd::ElementG1 {
        ckd::ElementG1::from_compressed(&self.0).unwrap()
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        match self {
            dtos::PublicKey::Secp256k1(secp256k1_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::SECP256K1,
                secp256k1_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Ed25519(ed25519_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                ed25519_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Bls12381(_bls12381_public_key) => {
                // This conversion is not possible
                unreachable!()
            }
        }
    }
}

pub async fn get_state(contract: &Contract) -> ProtocolContractState {
    contract.view("state").await.unwrap().json().unwrap()
}

pub async fn generate_participant_and_submit_attestation(
    worker: &Worker<Sandbox>,
    contract: &Contract,
) -> (Account, AccountId, ParticipantInfo) {
    let (new_account, account_id) = gen_account(worker).await;
    let new_participant = gen_participant_info();

    // Submit attestation for the new participant, otherwise
    // the contract will reject the resharing.
    submit_participant_info(
        &new_account,
        contract,
        &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        &new_participant.sign_pk.into_interface_type(),
    )
    .await
    .expect("Attestation submission for new account must succeed.");
    (new_account, account_id, new_participant)
}
