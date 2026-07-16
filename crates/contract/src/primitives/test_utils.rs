use super::domain::DomainRegistry;
use crate::{
    crypto_shared::types::{PublicKeyExtended, serializable::SerializableEdwardsPoint},
    primitives::{
        key_state::AuthenticatedParticipantId,
        participants::{ParticipantInfo, Participants},
        thresholds::{
            ProposedThresholdParameters, Threshold, ThresholdParameters,
            governance_threshold_lower_relative_bound, governance_threshold_upper_relative_bound,
        },
    },
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey, NodeId, Protocol,
    ReconstructionThreshold,
};
use near_sdk::{test_utils::VMContextBuilder, testing_env};
use rand::{Rng, SeedableRng, distributions::Uniform, rngs::StdRng};
use std::collections::BTreeMap;
// Re-export for convenience

const ALL_PROTOCOLS: [Protocol; 4] = [
    Protocol::CaitSith,
    Protocol::Frost,
    Protocol::ConfidentialKeyDerivation,
    Protocol::DamgardEtAl,
];
pub const NUM_PROTOCOLS: usize = ALL_PROTOCOLS.len();

/// Default per-domain reconstruction threshold used by test fixtures. `2` is
/// the minimum valid value (`validate_domain_threshold` requires `t >= 2`).
/// Works for participant counts `>= 3`, which is what `gen_threshold_params`
/// produces — needed because fixtures may include `DamgardEtAl` domains,
/// whose `2t - 1 <= n` bound becomes `n >= 3` at `t = 2`.
pub const DEFAULT_TEST_RECONSTRUCTION_THRESHOLD: ReconstructionThreshold =
    ReconstructionThreshold::new(2);

/// Generates a valid DomainRegistry covering all protocols, with num_domains total.
pub fn gen_domain_registry(num_domains: usize) -> DomainRegistry {
    let mut domains = Vec::new();
    for i in 0..num_domains {
        let protocol = ALL_PROTOCOLS[i % ALL_PROTOCOLS.len()];
        domains.push(DomainConfig {
            id: DomainId(i as u64 * 2),
            protocol,
            reconstruction_threshold: DEFAULT_TEST_RECONSTRUCTION_THRESHOLD,
            purpose: infer_purpose_from_protocol(protocol),
        });
    }
    DomainRegistry::from_raw_validated(domains, num_domains as u64 * 2).unwrap()
}

/// Generates a valid list of domains to add to the given registry.
pub fn gen_domains_to_add(registry: &DomainRegistry, num_domains: usize) -> Vec<DomainConfig> {
    let mut new_domains = Vec::new();
    for i in 0..num_domains {
        let protocol = ALL_PROTOCOLS[i % ALL_PROTOCOLS.len()];
        new_domains.push(DomainConfig {
            id: DomainId(registry.next_domain_id() + i as u64),
            protocol,
            reconstruction_threshold: DEFAULT_TEST_RECONSTRUCTION_THRESHOLD,
            purpose: infer_purpose_from_protocol(protocol),
        });
    }
    new_domains
}
fn gen_random_edwards_point() -> (SerializableEdwardsPoint, CompressedEdwardsY) {
    let rng = rand::thread_rng();
    let edwards_point = SerializableEdwardsPoint::random(rng);
    (edwards_point, edwards_point.compress())
}

pub fn bogus_ed25519_public_key_extended() -> PublicKeyExtended {
    let (edwards_point, compressed_edwards_point) = gen_random_edwards_point();
    let near_public_key_compressed = near_sdk::PublicKey::from_parts(
        near_sdk::CurveType::ED25519,
        compressed_edwards_point.as_bytes().into(),
    )
    .unwrap();

    PublicKeyExtended::Ed25519 {
        near_public_key_compressed,
        edwards_point,
    }
}

pub fn bogus_ed25519_public_key() -> near_mpc_contract_interface::types::Ed25519PublicKey {
    let (_, compressed_edwards_point) = gen_random_edwards_point();
    near_mpc_contract_interface::types::Ed25519PublicKey::from(compressed_edwards_point)
}

pub fn bogus_ed25519_near_public_key() -> near_sdk::PublicKey {
    let (_, compressed_edwards_point) = gen_random_edwards_point();
    near_sdk::PublicKey::from_parts(
        near_sdk::CurveType::ED25519,
        compressed_edwards_point.as_bytes().into(),
    )
    .unwrap()
}

#[test]
fn test_random_public_key() {
    let pk1 = bogus_ed25519_near_public_key();
    let pk2 = bogus_ed25519_near_public_key();
    assert_ne!(pk1, pk2, "Random keys should be different");
}

pub fn gen_account_id() -> AccountId {
    let lower_case = Uniform::new_inclusive(b'a', b'z');
    let random_string: String = rand::thread_rng()
        .sample_iter(&lower_case)
        .take(12)
        .map(char::from)
        .collect();
    let account_id: String = format!("dummy.account.{}", random_string);
    account_id.parse().unwrap()
}

#[test]
fn test_random_account_id() {
    let acc1 = gen_account_id();
    let acc2 = gen_account_id();
    assert_ne!(acc1, acc2, "Random keys should be different");
}

pub fn gen_participant(i: usize) -> (AccountId, ParticipantInfo) {
    (
        gen_account_id(),
        ParticipantInfo {
            url: format!("https://www.near{}.com", i),
            tls_public_key: bogus_ed25519_public_key(),
        },
    )
}

pub fn gen_accounts_and_info(n: usize) -> BTreeMap<AccountId, ParticipantInfo> {
    (0..n).map(gen_participant).collect()
}

pub fn gen_participants(n: usize) -> Participants {
    let mut participants = Participants::new();
    for i in 0..n {
        let (account_id, info) = gen_participant(i);
        let _ = participants.insert(account_id, info);
    }
    participants
}

/// Builds a [`NodeId`] with a placeholder (bogus) account public key.
pub fn create_node_id(account_id: &AccountId, tls_public_key: &Ed25519PublicKey) -> NodeId {
    NodeId {
        account_id: account_id.clone(),
        tls_public_key: tls_public_key.clone(),
        account_public_key: bogus_ed25519_public_key(),
    }
}

/// Builds a [`NodeId`] for `account_id` with placeholder (bogus) TLS and account public keys,
/// for tests that do not exercise those keys.
pub fn node_id_for(account_id: &AccountId) -> NodeId {
    create_node_id(account_id, &bogus_ed25519_public_key())
}

/// Sets `account_id` as the signer and authenticates it against `participants`.
pub fn authenticate_as(
    account_id: &AccountId,
    participants: &Participants,
) -> AuthenticatedParticipantId {
    let mut ctx = VMContextBuilder::new();
    ctx.signer_account_id(account_id.clone());
    testing_env!(ctx.build());
    AuthenticatedParticipantId::new(participants).unwrap()
}

/// Build `n` participants and pre-authenticate each, returning the set alongside
/// each participant's [`AuthenticatedParticipantId`].
pub fn gen_authenticated_participants(n: usize) -> (Participants, Vec<AuthenticatedParticipantId>) {
    let participants = gen_participants(n);
    let auth_ids = participants
        .participants()
        .iter()
        .map(|(account_id, _, _)| authenticate_as(account_id, &participants))
        .collect();
    (participants, auth_ids)
}

pub fn gen_seed() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
}

pub fn gen_threshold_params(max_n: usize) -> ThresholdParameters {
    // Lower bound is 3 (not 2) so the produced parameters are compatible with
    // every protocol — `DamgardEtAl` requires `n >= 2t - 1`, which forces
    // `n >= 3` even at the minimum `t = 2`.
    let mut rng = StdRng::seed_from_u64(42);
    let n: usize = rng.gen_range(3..max_n + 1);
    let k_min = governance_threshold_lower_relative_bound(n as u64) as usize;
    let k_max = governance_threshold_upper_relative_bound(n as u64) as usize;
    let k = rng.gen_range(k_min..k_max + 1);
    ThresholdParameters::new(gen_participants(n), Threshold::new(k as u64)).unwrap()
}

/// Like [`gen_threshold_params`] but wrapped as a proposal with an empty
/// (no-change) set of per-domain threshold updates — the shape
/// `vote_new_parameters` accepts.
pub fn gen_proposed_threshold_params(max_n: usize) -> ProposedThresholdParameters {
    ProposedThresholdParameters::new(gen_threshold_params(max_n), BTreeMap::new())
}

/// Infer a default purpose from the protocol.
/// Used during migration from old state that lacks the `purpose` field.
pub fn infer_purpose_from_protocol(protocol: Protocol) -> DomainPurpose {
    match protocol {
        Protocol::ConfidentialKeyDerivation => DomainPurpose::CKD,
        Protocol::CaitSith | Protocol::Frost | Protocol::DamgardEtAl => DomainPurpose::Sign,
    }
}
