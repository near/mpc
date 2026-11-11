//! Test fixtures shared by more than one of the per-feature test modules in this tree.

use crate::MpcContract;
use crate::dto_mapping::IntoInterfaceType;
use crate::errors::Error;
use crate::foreign_chains_metadata::ForeignChainsMetadata;
use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
use crate::primitives::participants::Participants;
use crate::primitives::test_utils::{
    NUM_PROTOCOLS, bogus_ed25519_near_public_key, bogus_tee_verifier_account_id,
    gen_participant_url, gen_participants, infer_purpose_from_protocol, node_for,
};
use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
use crate::state::ProtocolContractState;
use crate::state::test_utils::{gen_initializing_state, gen_resharing_state, gen_running_state};
use crate::storage_keys::StorageKey;
use dtos::{
    Attestation, Curve, DomainConfig, DomainId, DomainPurpose, MockAttestation, Protocol,
    ReconstructionThreshold,
};
use elliptic_curve::{Field as _, Group};
use k256::elliptic_curve;
use mpc_attestation::attestation::MockAttestation as MpcMockAttestation;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_sdk::store::{IterableMap, Lazy, LookupMap};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{NearToken, VMContext, env, testing_env};
use rand::SeedableRng;
use rand_core::CryptoRngCore;
use std::assert_matches;
use std::collections::BTreeMap;
use std::{str::FromStr, time::Duration};
use threshold_signatures::confidential_key_derivation as ckd;
use threshold_signatures::frost_core::Group as _;
use threshold_signatures::frost_ed25519::Ed25519Group;
use threshold_signatures::frost_secp256k1::Secp256K1Group;

pub(crate) const FORWARDER_ACCOUNT_ID: &str = "forwarder.near";

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
    let domain_id = DomainId::default();
    // RobustEcdsa requires 2t - 1 <= n; with n=4, the max valid t is 2.
    let reconstruction_threshold = match protocol {
        Protocol::RobustEcdsa => ReconstructionThreshold::new(2),
        _ => ReconstructionThreshold::new(3),
    };
    let ContractWithKeys {
        contract,
        mut secret_keys,
    } = running_contract_with_domains(
        vec![DomainConfig {
            id: domain_id,
            protocol,
            reconstruction_threshold,
            purpose,
        }],
        rng,
    );
    let sk = secret_keys.remove(&domain_id).unwrap();

    let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
    let context = VMContextBuilder::new()
        .attached_deposit(NearToken::from_yoctonear(1))
        .predecessor_account_id(contract_account_id.clone())
        .current_account_id(contract_account_id)
        .build();
    testing_env!(context.clone());
    (context, contract, sk)
}

pub(crate) struct ContractWithKeys {
    pub(crate) contract: MpcContract,
    pub(crate) secret_keys: BTreeMap<DomainId, SharedSecretKey>,
}

/// Initializes a Running contract with `domains`, each under a fresh key, and
/// attests all of its four participants.
pub(crate) fn running_contract_with_domains(
    domains: Vec<DomainConfig>,
    rng: &mut impl CryptoRngCore,
) -> ContractWithKeys {
    let mut secret_keys = BTreeMap::new();
    let mut keys = Vec::new();
    for domain in &domains {
        let (pk, sk) = make_public_key_for_curve(Curve::from(domain.protocol), rng);
        secret_keys.insert(domain.id, sk);
        keys.push(KeyForDomain {
            domain_id: domain.id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        });
    }
    let next_domain_id = domains
        .iter()
        .map(|domain| domain.id.0 + 1)
        .max()
        .unwrap_or_default();
    let parameters =
        GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
            .unwrap();
    let mut contract = MpcContract::init_running(
        domains,
        DomainId(next_domain_id),
        (&Keyset::new(EpochId::new(0), keys)).into_dto_type(),
        (&parameters).into_dto_type(),
        bogus_tee_verifier_account_id(),
        None,
    )
    .unwrap();
    prepay_and_attest_all_participants(&mut contract);
    ContractWithKeys {
        contract,
        secret_keys,
    }
}

/// Moves the contract from Running to Initializing with every
/// participant's vote for a new domain.
pub(crate) fn start_adding_a_domain(contract: &mut MpcContract) {
    let new_domain = DomainConfig {
        id: contract
            .protocol_state
            .domain_registry()
            .unwrap()
            .next_domain_id(),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::Sign,
    };
    for account_id in participant_account_ids(contract) {
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id)
                .build()
        );
        contract.vote_add_domains(vec![new_domain.clone()]).unwrap();
    }
    assert_matches!(
        contract.protocol_state,
        ProtocolContractState::Initializing(_)
    );
}

/// Initializes a Running contract with `parameters` and the single `domain`, under a fresh key.
pub(crate) fn init_running_with_domain(
    parameters: &GovernanceThresholdParameters,
    domain: DomainConfig,
) -> MpcContract {
    let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
    let (pk, _) = make_public_key_for_curve(Curve::from(domain.protocol), &mut rng);
    let keyset = Keyset::new(
        EpochId::new(0),
        vec![KeyForDomain {
            domain_id: domain.id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        }],
    );
    let next_domain_id = DomainId(domain.id.0 + 1);
    MpcContract::init_running(
        vec![domain],
        next_domain_id,
        (&keyset).into_dto_type(),
        parameters.into_dto_type(),
        bogus_tee_verifier_account_id(),
        None,
    )
    .unwrap()
}

/// Prepays a grant for every participant and submits a valid mock attestation from each, as
/// their nodes do right after initialization.
pub(crate) fn prepay_and_attest_all_participants(contract: &mut MpcContract) {
    let participants = contract
        .protocol_state
        .threshold_parameters()
        .unwrap()
        .participants()
        .clone();
    for (account_id, _, info) in participants.participants() {
        prepay_and_submit_mock_attestation(contract, account_id, info.tls_public_key.clone())
            .expect("a participant's valid mock attestation should be accepted");
    }
    // Writes the attestations to storage as the end of their transactions would. Left pending,
    // they are written when the contract is dropped, against the gas of the test's last call.
    contract.tee_state.nodes.flush();
    contract.available_attestation_grants.flush();
}

/// Prepays one attestation-storage grant for `account_id`, then submits a valid mock
/// attestation from it, signed with a fresh account key.
pub(crate) fn prepay_and_submit_mock_attestation(
    contract: &mut MpcContract,
    account_id: &AccountId,
    tls_public_key: dtos::Ed25519PublicKey,
) -> Result<(), Error> {
    let fee = NearToken::from_millinear(u128::from(
        contract.config.attestation_storage_fee_millinear,
    ));
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id(account_id.clone())
            .attached_deposit(fee)
            .block_timestamp(env::block_timestamp())
            .build()
    );
    contract
        .prepay_attestation_storage(account_id.clone(), 1)
        .expect("prepaying one grant should succeed");
    testing_env!(
        VMContextBuilder::new()
            .signer_account_id(account_id.clone())
            .predecessor_account_id(account_id.clone())
            .signer_account_pk(bogus_ed25519_near_public_key())
            .block_timestamp(env::block_timestamp())
            .build()
    );
    contract
        .submit_participant_info(Attestation::Mock(MockAttestation::Valid), tls_public_key)
        .map(|_| ())
}

pub(crate) fn must_get_attested_signer_key(
    contract: &MpcContract,
    tls_public_key: &dtos::Ed25519PublicKey,
) -> near_sdk::PublicKey {
    let node = contract
        .tee_state
        .nodes
        .get(tls_public_key)
        .expect("a node must be attested under the TLS key");
    near_sdk::PublicKey::from(node.signer_public_key.clone())
}

/// Temporarily sets the testing environment so that calls appear
/// to come from an attested MPC node registered in the contract's `tee_state`.
pub(crate) fn with_active_participant_and_attested_context(contract: &MpcContract) {
    let node = contract
        .protocol_state
        .active_participants()
        .participants()
        .iter()
        .find_map(|(account_id, _, participant_info)| {
            contract
                .tee_state
                .node_of(account_id, &participant_info.tls_public_key)
        })
        .expect("No attested participants in tee_state");
    testing_env!(
        VMContextBuilder::new()
            .signer_account_id(node.owner.clone())
            .predecessor_account_id(node.owner.clone())
            .signer_account_pk(node.signer_public_key.clone().into())
            .attached_deposit(NearToken::from_yoctonear(1))
            .build()
    );
}

pub(crate) fn setup_tee_test_contract(
    num_participants: usize,
    threshold_value: u64,
) -> (MpcContract, Participants, AccountId) {
    let participants = gen_participants(num_participants);
    let first_participant_id = participants.participants()[0].0.clone();

    let threshold = GovernanceThreshold::new(threshold_value);
    let parameters = GovernanceThresholdParameters::new(participants.clone(), threshold).unwrap();
    let mut contract = MpcContract::init(
        (&parameters).into_dto_type(),
        bogus_tee_verifier_account_id(),
        None,
    )
    .unwrap();
    prepay_and_attest_all_participants(&mut contract);
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

pub(crate) fn must_attest_new_node(
    contract: &mut MpcContract,
    account_id: &AccountId,
) -> dtos::NodeInfo {
    let node = node_for(account_id);
    contract
        .tee_state
        .verify_and_store_mock(
            node.clone(),
            MpcMockAttestation::Valid,
            Duration::from_secs(contract.config.tee_upgrade_deadline_duration_seconds),
        )
        .expect("attestation insertion should succeed");
    node
}

pub(crate) fn destination_of(node: &dtos::NodeInfo) -> dtos::DestinationNodeInfo {
    dtos::DestinationNodeInfo {
        signer_account_pk: node.account_public_key.clone(),
        destination_node_info: dtos::ParticipantInfo {
            url: gen_participant_url(0),
            tls_public_key: node.tls_public_key.clone(),
        },
    }
}

/// Returns a Running contract whose current call has its only participant as signer and
/// [`FORWARDER_ACCOUNT_ID`] as predecessor.
pub(crate) fn running_contract_called_by_participant_via_forwarder() -> MpcContract {
    let running_state = gen_running_state(1);
    let participant = running_state.parameters.participants().participants()[0]
        .0
        .clone();
    let contract =
        MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

    let ctx = VMContextBuilder::new()
        .signer_account_id(participant)
        .predecessor_account_id(FORWARDER_ACCOUNT_ID.parse().unwrap())
        .build();
    testing_env!(ctx);

    contract
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
            contract_update_votes: Default::default(),
            config: Default::default(),
            tee_state: Default::default(),
            node_migrations: Default::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: bogus_tee_verifier_account_id(),
            tee_verifier_votes: Default::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: Default::default(),
            pending_verify_foreign_tx_v2_requests: Default::default(),
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

pub(crate) fn running_state() -> ProtocolContractState {
    ProtocolContractState::Running(gen_running_state(NUM_DOMAINS))
}

pub(crate) fn resharing_state() -> ProtocolContractState {
    ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1)
}

pub(crate) fn initializing_state() -> ProtocolContractState {
    ProtocolContractState::Initializing(
        gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1,
    )
}

pub(crate) fn contract_with_participants(
    protocol_state: ProtocolContractState,
) -> (MpcContract, Vec<AccountId>) {
    let contract = MpcContract::new_from_protocol_state(protocol_state);
    let participants = participant_account_ids(&contract);
    (contract, participants)
}
