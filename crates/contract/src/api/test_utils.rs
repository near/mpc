//! Test fixtures shared by more than one of the per-feature test modules in this tree.

use crate::MpcContract;
use crate::dto_mapping::IntoInterfaceType;
use crate::errors::Error;
use crate::foreign_chains_metadata::ForeignChainsMetadata;
use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
use crate::primitives::participants::Participants;
use crate::primitives::test_utils::{NUM_PROTOCOLS, gen_participants, infer_purpose_from_protocol};
use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
use crate::state::ProtocolContractState;
use crate::state::test_utils::gen_running_state;
use crate::storage_keys::StorageKey;
use crate::tee::test_utils::Environment;
use dtos::{
    Attestation, Curve, DomainConfig, DomainId, DomainPurpose, MockAttestation, Protocol,
    ReconstructionThreshold,
};
use elliptic_curve::{Field as _, Group};
use k256::elliptic_curve;
use near_account_id::AccountId;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;
use near_sdk::store::{IterableMap, Lazy, LookupMap};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{NearToken, VMContext, testing_env};
use rand_core::CryptoRngCore;
use std::collections::BTreeSet;
use std::str::FromStr;
use threshold_signatures::confidential_key_derivation as ckd;
use threshold_signatures::frost_core::Group as _;
use threshold_signatures::frost_ed25519::Ed25519Group;
use threshold_signatures::frost_secp256k1::Secp256K1Group;

#[derive(Debug)]
pub(crate) enum SharedSecretKey {
    Secp256k1(k256::Scalar),
    #[expect(dead_code)]
    Ed25519(curve25519_dalek::Scalar),
    Bls12381(ckd::Scalar),
}

pub(crate) fn new_secp256k1(
    rng: &mut impl CryptoRngCore,
) -> (dtos::Secp256k1PublicKey, k256::Scalar) {
    let scalar = k256::Scalar::random(rng);
    let public_key_element = Secp256K1Group::generator() * scalar;

    let pk = dtos::Secp256k1PublicKey::try_from(public_key_element.to_affine())
        .expect("non-identity group element is a valid public key");

    (pk, scalar)
}

pub(crate) fn new_ed25519(
    rng: &mut impl CryptoRngCore,
) -> (dtos::Ed25519PublicKey, curve25519_dalek::Scalar) {
    let scalar = curve25519_dalek::Scalar::random(rng);
    let public_key_element = Ed25519Group::generator() * scalar;

    let pk = dtos::Ed25519PublicKey::from(public_key_element.compress());

    (pk, scalar)
}

pub(crate) fn new_bls12381g2(
    rng: &mut impl CryptoRngCore,
) -> (dtos::Bls12381G2PublicKey, ckd::Scalar) {
    let scalar = ckd::Scalar::random(rng);
    let public_key_element = ckd::ElementG2::generator() * scalar;

    let pk = dtos::Bls12381G2PublicKey::from(&public_key_element);

    (pk, scalar)
}

pub(crate) fn make_public_key_for_curve(
    curve: Curve,
    rng: &mut impl CryptoRngCore,
) -> (dtos::PublicKey, SharedSecretKey) {
    match curve {
        Curve::Secp256k1 => {
            let (pk, sk) = new_secp256k1(rng);
            (pk.into(), SharedSecretKey::Secp256k1(sk))
        }
        Curve::Edwards25519 => {
            let (pk, sk) = new_ed25519(rng);
            (pk.into(), SharedSecretKey::Ed25519(sk))
        }
        Curve::Bls12381 => {
            let (pk, sk) = new_bls12381g2(rng);
            (pk.into(), SharedSecretKey::Bls12381(sk))
        }
    }
}

pub(crate) fn basic_setup(
    curve: Curve,
    rng: &mut impl CryptoRngCore,
) -> (VMContext, MpcContract, SharedSecretKey) {
    let protocol = match curve {
        Curve::Secp256k1 => Protocol::CaitSith,
        Curve::Edwards25519 => Protocol::Frost,
        Curve::Bls12381 => Protocol::ConfidentialKeyDerivation,
    };
    basic_setup_with_protocol(protocol, infer_purpose_from_protocol(protocol), rng)
}

pub(crate) fn basic_setup_with_protocol(
    protocol: Protocol,
    purpose: DomainPurpose,
    rng: &mut impl CryptoRngCore,
) -> (VMContext, MpcContract, SharedSecretKey) {
    let curve = Curve::from(protocol);
    let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
    let context = VMContextBuilder::new()
        .attached_deposit(NearToken::from_yoctonear(1))
        .predecessor_account_id(contract_account_id.clone())
        .current_account_id(contract_account_id)
        .build();
    testing_env!(context.clone());
    let domain_id = DomainId::default();
    // DamgardEtAl requires 2t - 1 <= n; with n=4, the max valid t is 2.
    let reconstruction_threshold = match protocol {
        Protocol::DamgardEtAl => ReconstructionThreshold::new(2),
        _ => ReconstructionThreshold::new(3),
    };
    let domains = vec![DomainConfig {
        id: domain_id,
        protocol,
        reconstruction_threshold,
        purpose,
    }];
    let epoch_id = EpochId::new(0);
    let (pk, sk) = make_public_key_for_curve(curve, rng);
    let key_for_domain = KeyForDomain {
        domain_id,
        key: pk.try_into().unwrap(),
        attempt: AttemptId::new(),
    };
    let keyset = Keyset::new(epoch_id, vec![key_for_domain]);
    let parameters =
        GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
            .unwrap();
    let contract =
        MpcContract::init_running(domains, 1, keyset, (&parameters).into_dto_type(), None).unwrap();
    (context, contract, sk)
}

/// Temporarily sets the testing environment so that calls appear
/// to come from an attested MPC node registered in the contract's `tee_state`.
/// Returns the [`AccountId`] of the node used.
pub(crate) fn with_active_participant_and_attested_context(contract: &MpcContract) -> AccountId {
    let active_participant_pks: Vec<dtos::Ed25519PublicKey> = contract
        .protocol_state
        .active_participants()
        .participants()
        .iter()
        .map(|(_, _, participant_info)| participant_info.tls_public_key.clone())
        .collect();

    let node_id = contract
        .tee_state
        .stored_attestations
        .iter()
        .find(|(public_key, _)| active_participant_pks.contains(public_key))
        .expect("No attested participants in tee_state")
        .1
        .node_id
        .clone();

    // Build a new simulated environment with this node as caller.
    // Set signer_account_pk to match the mock attestation (account_public_key == tls_public_key).
    let mut ctx_builder = VMContextBuilder::new();
    ctx_builder
        .signer_account_id(node_id.account_id.clone())
        .predecessor_account_id(node_id.account_id.clone())
        .signer_account_pk(near_sdk::PublicKey::from(
            node_id.account_public_key.clone(),
        ))
        .attached_deposit(NearToken::from_yoctonear(1));

    testing_env!(ctx_builder.build());
    node_id.account_id.clone()
}

pub(crate) fn setup_tee_test_contract(
    num_participants: usize,
    threshold_value: u64,
) -> (MpcContract, Participants, AccountId) {
    let participants = gen_participants(num_participants);
    let first_participant_id = participants.participants()[0].0.clone();

    let context = VMContextBuilder::new()
        .signer_account_id(first_participant_id.clone())
        .predecessor_account_id(first_participant_id.clone())
        .attached_deposit(NearToken::from_near(1))
        .build();
    testing_env!(context);

    let threshold = GovernanceThreshold::new(threshold_value);
    let parameters = GovernanceThresholdParameters::new(participants.clone(), threshold).unwrap();
    let contract = MpcContract::init((&parameters).into_dto_type(), None).unwrap();

    (contract, participants, first_participant_id)
}

pub(crate) fn submit_attestation(
    contract: &mut MpcContract,
    participants: &Participants,
    participant_index: usize,
    is_valid: bool,
) -> Result<(), Error> {
    let participants_list = participants.participants();
    let (account_id, _, participant_info) = &participants_list[participant_index];
    let attestation = if is_valid {
        MockAttestation::Valid
    } else {
        MockAttestation::Invalid
    };

    let dto_public_key = participant_info.tls_public_key.clone();

    let participant_context = VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .predecessor_account_id(account_id.clone())
        .build();
    testing_env!(participant_context);

    contract
        .submit_participant_info(Attestation::Mock(attestation), dto_public_key)
        .map(|_| ())
}

pub(crate) fn submit_valid_attestations(
    contract: &mut MpcContract,
    participants: &Participants,
    participant_indices: &[usize],
) {
    for &participant_index in participant_indices {
        let result = submit_attestation(contract, participants, participant_index, true);
        assert!(
            result.is_ok(),
            "submit_participant_info should succeed with valid attestation for participant {}",
            participant_index
        );
    }
}

pub(crate) fn forwarded_participant_call_contract() -> MpcContract {
    let running_state = gen_running_state(1);
    let participant = running_state.parameters.participants().participants()[0]
        .0
        .clone();
    let contract =
        MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

    let ctx = VMContextBuilder::new()
        .signer_account_id(participant)
        .predecessor_account_id("forwarder.near".parse().unwrap())
        .build();
    testing_env!(ctx);

    contract
}

/// Votes `chain` into the on-chain RPC whitelist with the signing threshold of participants.
pub(crate) fn whitelist_chain(contract: &mut MpcContract, chain: dtos::ForeignChain) {
    let batch = NonEmptyBTreeMap::new(chain, ::test_utils::contract_types::dummy_chain_entry());
    let threshold = contract.threshold().unwrap().value() as usize;
    for account_id in participant_account_ids(contract).iter().take(threshold) {
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_update_foreign_chain_providers(batch.clone())
            .expect("vote should succeed");
    }
}

pub(crate) fn register_foreign_chains_config_for(
    contract: &mut MpcContract,
    account_id: &AccountId,
    chains: impl IntoIterator<Item = dtos::ForeignChain>,
) {
    let foreign_chains_config: dtos::ForeignChainsConfig =
        chains.into_iter().collect::<BTreeSet<_>>().into();
    // In mock setup, account_public_key == tls_public_key.
    let tls_key = contract
        .protocol_state
        .threshold_parameters()
        .unwrap()
        .participants()
        .info(account_id)
        .expect("account must be a participant")
        .tls_public_key
        .clone();
    let mut env = Environment::new(None, Some(account_id.clone()), None);
    env.set_pk(near_sdk::PublicKey::from(tls_key));
    contract
        .register_foreign_chains_config(foreign_chains_config)
        .expect("register should succeed");
}

impl MpcContract {
    pub(crate) fn new_from_protocol_state(protocol_state: ProtocolContractState) -> Self {
        MpcContract {
            protocol_state,
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            accept_requests: true,
            proposed_updates: Default::default(),
            node_foreign_chain_support: Default::default(),
            config: Default::default(),
            tee_state: Default::default(),
            node_migrations: Default::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: None,
            tee_verifier_votes: Default::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        }
    }
}

pub(crate) const NUM_GENERATED_DOMAINS: usize = 1;
pub(crate) const NUM_DOMAINS: usize = 2 * NUM_PROTOCOLS;

pub(crate) fn participant_account_ids(contract: &MpcContract) -> Vec<AccountId> {
    contract
        .protocol_state
        .threshold_parameters()
        .unwrap()
        .participants()
        .participants()
        .iter()
        .map(|(account_id, _, _)| account_id.clone())
        .collect()
}
