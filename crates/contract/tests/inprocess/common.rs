use mpc_contract::{
    MpcContract,
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantId, ParticipantInfo},
        test_utils::gen_participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, InitConfig, Protocol, ProtocolContractState,
    ReconstructionThreshold,
};
use near_sdk::{NearToken, VMContext, test_utils::VMContextBuilder, testing_env};
use std::str::FromStr;

use assert_matches::assert_matches;

/// A freshly built `Running` contract plus the data tests need to drive it.
pub struct RunningContract {
    pub contract: MpcContract,
    pub participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    pub parameters: ThresholdParameters,
}

/// A VM context whose signer and predecessor are `account_id` — i.e. the call originates from
/// that participant's own account — keeping the current block timestamp.
pub fn participant_context(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .predecessor_account_id(account_id.clone())
        .block_timestamp(near_sdk::env::block_timestamp())
        .build()
}

/// Builds a contract already in `Running` with a single Sign domain and `participant_count`
/// participants.
pub fn build_running_contract(
    participant_count: usize,
    threshold: u64,
    init_config: Option<InitConfig>,
) -> RunningContract {
    let participants = gen_participants(participant_count);
    let participants_list = participants.participants().clone();
    let parameters = ThresholdParameters::new(participants, Threshold::new(threshold))
        .expect("failed to create threshold parameters");

    let near_public_key =
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, vec![1u8; 64]).unwrap();
    let keyset = Keyset::new(
        EpochId::new(5),
        vec![KeyForDomain {
            domain_id: DomainId::default(),
            key: PublicKeyExtended::Secp256k1 { near_public_key },
            attempt: AttemptId::new(),
        }],
    );
    let domains = vec![DomainConfig {
        id: DomainId::default(),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(2),
        purpose: DomainPurpose::Sign,
    }];

    let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
    testing_env!(
        VMContextBuilder::new()
            .attached_deposit(NearToken::from_yoctonear(1))
            .predecessor_account_id(contract_account_id.clone())
            .current_account_id(contract_account_id)
            .build()
    );

    let contract =
        MpcContract::init_running(domains, 1, keyset, parameters.clone().into(), init_config)
            .unwrap();

    RunningContract {
        contract,
        participants: participants_list,
        parameters,
    }
}

/// Drives `contract` out of `Running` into `Initializing` by having every participant vote to
/// add a new domain.
pub fn transition_to_initializing(
    contract: &mut MpcContract,
    participants: &[(AccountId, ParticipantId, ParticipantInfo)],
) {
    for (account_id, _, _) in participants {
        testing_env!(participant_context(account_id));
        contract
            .vote_add_domains(vec![DomainConfig {
                id: DomainId(1),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            }])
            .unwrap();
    }
    assert_matches!(contract.state(), ProtocolContractState::Initializing(_));
}
