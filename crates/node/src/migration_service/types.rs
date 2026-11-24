use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    BackupServiceInfo, DestinationNodeInfo, Ed25519PublicKey,
};
use near_mpc_crypto_types::Keyset;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{NodeStatus, ParticipantStatus},
    indexer::{migrations::ContractMigrationInfo, participants::ContractState},
};

#[derive(PartialEq, Debug, Clone)]
pub struct MigrationInfo {
    /// The TLS key of this account's backup service, kept only while the contract holds a valid
    /// attestation for it.
    pub backup_service_tls_key: Option<VerifyingKey>,
    pub active_migration: bool,
}

pub(crate) fn backup_service_tls_key(info: &BackupServiceInfo) -> Option<VerifyingKey> {
    VerifyingKey::try_from(&info.public_key)
        .inspect_err(|err| tracing::warn!(?err, "could not parse the backup service's TLS key"))
        .ok()
}

#[derive(Clone)]
pub(crate) struct OnboardingTask {
    pub job: OnboardingJob,
    pub cancellation_token: CancellationToken,
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) enum OnboardingJob {
    /// Onboarding is complete; nothing to do.
    Done,
    /// Waiting for contract or migration state to change.
    WaitForStateChange,
    /// Should start onboarding with the given keyset.
    Onboard(Keyset),
}

impl OnboardingJob {
    /// Constructs the onboarding job for the current node based on the contract and migration
    /// state
    ///
    /// Returns:
    /// - [`OnboardingJob::Done`] if the node is already active,
    /// - [`OnboardingJob::Onboard`] if onboarding should begin,
    /// - [`OnboardingJob::WaitForStateChange`] otherwise.
    pub fn new(
        my_migration_info: MigrationInfo,
        contract: ContractState,
        my_near_account_id: &AccountId,
        tls_public_key: &VerifyingKey,
    ) -> Self {
        match contract.node_status(my_near_account_id, tls_public_key) {
            ParticipantStatus::Inactive => OnboardingJob::WaitForStateChange,
            ParticipantStatus::Active(NodeStatus::Active) => OnboardingJob::Done,
            ParticipantStatus::Active(NodeStatus::Idle)
                if my_migration_info.active_migration
                    && let ContractState::Running(running_state) = contract
                    && running_state.resharing_state.is_none() =>
            {
                OnboardingJob::Onboard(running_state.keyset)
            }
            ParticipantStatus::Active(NodeStatus::Idle) => OnboardingJob::WaitForStateChange,
        }
    }
}

/// Whether the contract lists this node as the destination of its account's migration.
pub(crate) fn active_migration(
    my_account_id: &AccountId,
    my_p2p_public_key: &VerifyingKey,
    contract_state: &ContractMigrationInfo,
) -> bool {
    contract_state
        .get(my_account_id)
        .is_some_and(|(_, destination_node_info)| {
            infer_migration_status(my_p2p_public_key, destination_node_info)
        })
}

fn infer_migration_status(
    my_p2p_public_key: &VerifyingKey,
    destination_node_info: &Option<DestinationNodeInfo>,
) -> bool {
    let Some(info) = destination_node_info.as_ref() else {
        return false;
    };
    let registered_key = &info.destination_node_info.tls_public_key;
    match VerifyingKey::try_from(registered_key) {
        Ok(key) if key == *my_p2p_public_key => true,
        Ok(_) => {
            tracing::warn!(
                registered_tls_public_key = %String::from(registered_key),
                my_tls_public_key = %String::from(&Ed25519PublicKey::from(my_p2p_public_key)),
                "a destination node with a different TLS key is registered for this account; this node will not onboard (expected if this node is the migration source)"
            );
            false
        }
        Err(err) => {
            tracing::error!(
                ?err,
                registered_tls_public_key = %String::from(registered_key),
                "could not parse the registered destination node's TLS public key from chain"
            );
            false
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod tests {
    use ed25519_dalek::VerifyingKey;
    use mpc_contract::{
        primitives::test_utils::{bogus_ed25519_public_key, gen_participant},
        state::{
            ProtocolContractState,
            test_utils::{gen_initializing_state, gen_resharing_state, gen_running_state},
        },
    };
    use near_account_id::AccountId;
    use near_mpc_crypto_types::Keyset;

    use crate::{
        config,
        indexer::{migrations::ContractMigrationInfo, participants::ContractState},
    };

    use super::{
        BackupServiceInfo, DestinationNodeInfo, MigrationInfo, OnboardingJob, active_migration,
        backup_service_tls_key,
    };

    #[test]
    fn backup_service_tls_key__should_parse_the_contract_key() {
        // Given
        let public_key = bogus_ed25519_public_key();
        let expected = VerifyingKey::try_from(&public_key).unwrap();

        // When
        let tls_key = backup_service_tls_key(&BackupServiceInfo { public_key });

        // Then
        assert_eq!(tls_key, Some(expected));
    }

    #[test]
    fn active_migration__should_be_false_without_migration_info() {
        // Given
        let state = ContractMigrationInfo::default();
        let (account_id, _) = gen_participant(0);
        let p2p_public_key = VerifyingKey::try_from(&bogus_ed25519_public_key()).unwrap();

        // When
        let migrating = active_migration(&account_id, &p2p_public_key, &state);

        // Then
        assert!(!migrating);
    }

    #[test]
    fn active_migration__should_hold_only_for_this_nodes_destination_key() {
        // Given
        let mut state = ContractMigrationInfo::default();
        let (account_id_0, participant_info_0) = gen_participant(0);
        let (account_id_1, _) = gen_participant(1);
        let signer_account_pk = bogus_ed25519_public_key();
        let participant_tls_public_key = participant_info_0.tls_public_key.clone();
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: signer_account_pk.clone(),
            destination_node_info: participant_info_0.clone().into(),
        };

        state.insert(
            account_id_1.clone(),
            (
                Some(BackupServiceInfo {
                    public_key: bogus_ed25519_public_key(),
                }),
                Some(destination_node_info.clone()),
            ),
        );
        let participating_key = VerifyingKey::try_from(&participant_tls_public_key).unwrap();
        let non_participating_key = VerifyingKey::try_from(&signer_account_pk).unwrap();

        // When
        let migrating = [
            active_migration(&account_id_0, &participating_key, &state),
            active_migration(&account_id_1, &non_participating_key, &state),
            active_migration(&account_id_1, &participating_key, &state),
        ];

        // Then
        assert_eq!(migrating, [false, false, true]);
    }

    struct OnboardingJobConstructorTestCase {
        case: String,
        migration_info: MigrationInfo,
        contract: ContractState,
        node_id: TestNodeId,
        expected_outcome: OnboardingJob,
    }

    impl OnboardingJobConstructorTestCase {
        fn run(self) {
            assert_eq!(
                OnboardingJob::new(
                    self.migration_info,
                    self.contract,
                    &self.node_id.account_id,
                    &self.node_id.p2p_public_key
                ),
                self.expected_outcome,
                "case: {}",
                self.case
            );
        }
    }

    #[test]
    fn test_onboarding_job_participants() {
        let setup = OnboardingJobConstructorTestSetup::new();
        // Being a participant must always result in "Done"
        // initializing
        OnboardingJobConstructorTestCase {
            case: "Initializing Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.participant_node.clone(),
            expected_outcome: OnboardingJob::Done,
        }
        .run();

        // resharing
        OnboardingJobConstructorTestCase {
            case: "Resharing Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.participant_node.clone(),
            expected_outcome: OnboardingJob::Done,
        }
        .run();

        // running
        OnboardingJobConstructorTestCase {
            case: "Running Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.running.participant_node.clone(),
            expected_outcome: OnboardingJob::Done,
        }
        .run();
    }

    #[test]
    fn test_onboarding_job_inactive() {
        let setup = OnboardingJobConstructorTestSetup::new();
        // An inactive migration for an onboarding participant should always result in a "wait"
        // initializing
        OnboardingJobConstructorTestCase {
            case: "Initializing inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.onboarding_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
        // resharing
        OnboardingJobConstructorTestCase {
            case: "Resharing inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.onboarding_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
        // running
        OnboardingJobConstructorTestCase {
            case: "Running inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.running.onboarding_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
    }
    #[test]
    fn test_onboarding_job_active() {
        let setup = OnboardingJobConstructorTestSetup::new();
        // Running with active migration and an onboarding participant result in a "onboarding"
        OnboardingJobConstructorTestCase {
            case: "Running active".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.running.onboarding_node.clone(),
            expected_outcome: OnboardingJob::Onboard(setup.running_keyset.clone()),
        }
        .run();

        // but not when we have an ongoing key generation or resharing
        // initializing
        OnboardingJobConstructorTestCase {
            case: "Initializing active".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.onboarding_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
        // resharing
        OnboardingJobConstructorTestCase {
            case: "Resharing active".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.onboarding_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
    }

    #[test]
    fn test_onboarding_job_non_participant() {
        let setup = OnboardingJobConstructorTestSetup::new();
        // a non-participant must always wait for a state change
        // initializing
        OnboardingJobConstructorTestCase {
            case: "Non-participant initializing".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
        // resharing
        OnboardingJobConstructorTestCase {
            case: "Non-participant resharing".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
        // running
        OnboardingJobConstructorTestCase {
            case: "Non-participant running".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
    }
    #[test]
    fn test_onboarding_job_invalid() {
        let setup = OnboardingJobConstructorTestSetup::new();
        // invalid must result in Wait:
        OnboardingJobConstructorTestCase {
            case: "Invalid".into(),
            migration_info: setup.active_migration.clone(),
            contract: ContractState::Invalid,
            node_id: setup.running.participant_node.clone(),
            expected_outcome: OnboardingJob::WaitForStateChange,
        }
        .run();
    }

    impl OnboardingJobConstructorTestSetup {
        fn new() -> Self {
            let active_migration = MigrationInfo {
                backup_service_tls_key: None,
                active_migration: true,
            };
            let inactive_migration = MigrationInfo {
                backup_service_tls_key: None,
                active_migration: false,
            };
            let non_participant = config::tests::gen_participant();

            let onboarding_node_p2p_public_key = non_participant.p2p_public_key;
            let resharing = make_resharing_contract_case(onboarding_node_p2p_public_key);
            let (running, running_keyset) =
                make_running_contract_case(onboarding_node_p2p_public_key);
            let initializing = make_initializing_contract_case(onboarding_node_p2p_public_key);
            Self {
                active_migration,
                inactive_migration,
                running,
                resharing,
                initializing,
                running_keyset,
                non_participant: TestNodeId {
                    account_id: non_participant.near_account_id,
                    p2p_public_key: non_participant.p2p_public_key,
                },
            }
        }
    }

    struct OnboardingJobConstructorTestSetup {
        active_migration: MigrationInfo,
        inactive_migration: MigrationInfo,
        running: ContractCase,
        resharing: ContractCase,
        initializing: ContractCase,
        running_keyset: Keyset,
        non_participant: TestNodeId,
    }

    pub(crate) struct ContractCase {
        pub contract: ContractState,
        pub participant_node: TestNodeId,
        pub onboarding_node: TestNodeId,
    }
    impl ContractCase {
        fn new(contract: ContractState, onboarding_node_p2p_public_key: VerifyingKey) -> Self {
            let last_participant = contract
                .get_current_or_prospective_participants()
                .last()
                .unwrap()
                .clone();
            Self {
                contract,
                participant_node: TestNodeId {
                    account_id: last_participant.near_account_id.clone(),
                    p2p_public_key: last_participant.p2p_public_key,
                },
                onboarding_node: TestNodeId {
                    account_id: last_participant.near_account_id.clone(),
                    p2p_public_key: onboarding_node_p2p_public_key,
                },
            }
        }
    }

    #[derive(Clone)]
    pub(crate) struct TestNodeId {
        pub account_id: AccountId,
        pub p2p_public_key: VerifyingKey,
    }

    fn from_internal_contract_state(
        state: &ProtocolContractState,
        height: u64,
        port_override: Option<u16>,
    ) -> anyhow::Result<ContractState> {
        let dto: near_mpc_contract_interface::types::ProtocolContractState = state.clone().into();
        ContractState::from_contract_state(
            &dto,
            near_mpc_contract_interface::types::BlockHeight::new(height),
            port_override,
        )
    }

    const BLOCK_HEIGHT: u64 = 6;
    const PORT_OVERRIDE: Option<u16> = None;
    const NUM_DOMAINS: usize = 5;
    pub(crate) fn make_resharing_contract_case(
        onboarding_node_p2p_public_key: VerifyingKey,
    ) -> ContractCase {
        let contract = from_internal_contract_state(
            &ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1),
            BLOCK_HEIGHT,
            PORT_OVERRIDE,
        )
        .unwrap();
        ContractCase::new(contract, onboarding_node_p2p_public_key)
    }
    pub(crate) fn make_running_contract_case(
        onboarding_node_p2p_public_key: VerifyingKey,
    ) -> (ContractCase, Keyset) {
        let running_state = gen_running_state(NUM_DOMAINS);
        let contract = from_internal_contract_state(
            &ProtocolContractState::Running(running_state.clone()),
            BLOCK_HEIGHT,
            PORT_OVERRIDE,
        )
        .unwrap();

        (
            ContractCase::new(contract, onboarding_node_p2p_public_key),
            Keyset::from(&running_state.keyset),
        )
    }
    pub(crate) fn make_initializing_contract_case(
        onboarding_node_p2p_public_key: VerifyingKey,
    ) -> ContractCase {
        let contract = from_internal_contract_state(
            &ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, 0).1),
            BLOCK_HEIGHT,
            PORT_OVERRIDE,
        )
        .unwrap();
        ContractCase::new(contract, onboarding_node_p2p_public_key)
    }
}
