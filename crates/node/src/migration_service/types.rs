use ed25519_dalek::VerifyingKey;
use mpc_contract::{
    node_migrations::{BackupServiceInfo, DestinationNodeInfo},
    primitives::key_state::Keyset,
};
use near_sdk::AccountId;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{NodeStatus, ParticipantStatus},
    indexer::{migrations::ContractMigrationInfo, participants::ContractState},
    providers::PublicKeyConversion,
    trait_extensions::convert_to_contract_dto::TryIntoNodeType,
};

pub struct NodeBackupServiceInfo {
    pub p2p_key: VerifyingKey,
}

impl NodeBackupServiceInfo {
    pub fn from_contract(info: BackupServiceInfo) -> anyhow::Result<Self> {
        let p2p_key = match info.public_key.try_into_node_type() {
            Ok(res) => res,
            Err(err) => {
                anyhow::bail!("can't convert key: {}", err);
            }
        };
        Ok(Self { p2p_key })
    }
}

#[derive(PartialEq, Debug, Clone, Serialize)]
pub struct MigrationInfo {
    pub backup_service_info: Option<BackupServiceInfo>,
    pub active_migration: bool,
}

impl MigrationInfo {
    pub fn get_pk_backup_service(self) -> Option<VerifyingKey> {
        self.backup_service_info
            .and_then(|info| match NodeBackupServiceInfo::from_contract(info) {
                Ok(service) => Some(service.p2p_key),
                Err(err) => {
                    tracing::warn!("could not convert backup service info: {}", err);
                    None
                }
            })
    }
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
    /// - [`Done`] if the node is already active,
    /// - [`Onboard`] if onboarding should begin,
    /// - [`WaitForStateChange`] otherwise.
    pub fn new(
        my_migration_info: MigrationInfo,
        contract: ContractState,
        my_near_account_id: &AccountId,
        tls_public_key: &VerifyingKey,
    ) -> Self {
        match contract.node_status(my_near_account_id, tls_public_key) {
            ParticipantStatus::Inactive => OnboardingJob::WaitForStateChange,
            ParticipantStatus::Active(node_status) => match node_status {
                NodeStatus::Active => OnboardingJob::Done,
                NodeStatus::Idle => {
                    if my_migration_info.active_migration {
                        match contract {
                            ContractState::Invalid => OnboardingJob::WaitForStateChange,
                            ContractState::Initializing(_) => OnboardingJob::WaitForStateChange,
                            ContractState::Running(running_state) => {
                                if running_state.resharing_state.is_none() {
                                    OnboardingJob::Onboard(running_state.keyset)
                                } else {
                                    OnboardingJob::WaitForStateChange
                                }
                            }
                        }
                    } else {
                        OnboardingJob::WaitForStateChange
                    }
                }
            },
        }
    }
}

impl MigrationInfo {
    pub fn from_contract_state(
        my_account_id: &AccountId,
        my_p2p_public_key: &VerifyingKey,
        contract_state: &ContractMigrationInfo,
    ) -> Self {
        let (backup_service_info, active_migration) = match contract_state.get(my_account_id) {
            Some((backup_service_info, destination_node_info)) => (
                backup_service_info.clone(),
                infer_migration_status(my_p2p_public_key, destination_node_info),
            ),
            None => (None, false),
        };
        Self {
            backup_service_info,
            active_migration,
        }
    }
}

fn infer_migration_status(
    my_p2p_public_key: &VerifyingKey,
    destination_node_info: &Option<DestinationNodeInfo>,
) -> bool {
    destination_node_info
        .as_ref()
        .map(|info| {
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(
                &info.destination_node_info.sign_pk,
            )
            .inspect_err(|_| tracing::warn!(target: "Migration Service", "Error parsing public key from chain."))
            .is_ok_and(|key| key == *my_p2p_public_key)
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub mod tests {
    use ed25519_dalek::VerifyingKey;
    use mpc_contract::{
        node_migrations::{BackupServiceInfo, DestinationNodeInfo},
        primitives::{
            key_state::Keyset,
            test_utils::{
                bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_participant,
            },
        },
        state::{
            test_utils::{gen_initializing_state, gen_resharing_state, gen_running_state},
            ProtocolContractState,
        },
    };
    use near_sdk::AccountId;

    use crate::{
        config,
        indexer::{migrations::ContractMigrationInfo, participants::ContractState},
        providers::PublicKeyConversion,
        trait_extensions::convert_to_contract_dto::TryIntoNodeType,
    };

    use super::{MigrationInfo, OnboardingJob};

    #[test]
    fn test_migration_get_pk_backup_service() {
        let empty = MigrationInfo {
            backup_service_info: None,
            active_migration: true,
        };
        assert!(empty.get_pk_backup_service().is_none());

        let public_key = bogus_ed25519_public_key();
        let pk_converted = public_key.clone().try_into_node_type().unwrap();
        let backup_service_info = Some(BackupServiceInfo { public_key });
        let populated = MigrationInfo {
            backup_service_info,
            active_migration: true,
        };
        assert_eq!(populated.get_pk_backup_service(), Some(pk_converted))
    }

    #[test]
    fn test_migration_status_constructor_empty() {
        let state = ContractMigrationInfo::new();
        let (account_id, _) = gen_participant(0);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let p2p_public_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&signer_account_pk).unwrap();

        let res = MigrationInfo::from_contract_state(&account_id, &p2p_public_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, None);
    }

    #[test]
    fn test_migration_status_constructor_populated() {
        let mut state = ContractMigrationInfo::new();
        let (account_id_0, participant_info_0) = gen_participant(0);
        let (account_id_1, _) = gen_participant(1);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: signer_account_pk.clone(),
            destination_node_info: participant_info_0.clone(),
        };

        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };
        state.insert(
            account_id_1.clone(),
            (
                Some(backup_service_info.clone()),
                Some(destination_node_info.clone()),
            ),
        );
        let participating_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&participant_info_0.sign_pk)
                .unwrap();
        let non_participating_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&signer_account_pk).unwrap();

        let res = MigrationInfo::from_contract_state(&account_id_0, &participating_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, None);

        let res = MigrationInfo::from_contract_state(&account_id_1, &non_participating_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, Some(backup_service_info.clone()));

        let res = MigrationInfo::from_contract_state(&account_id_1, &participating_key, &state);
        assert!(res.active_migration);
        assert_eq!(res.backup_service_info, Some(backup_service_info.clone()));
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
                backup_service_info: None,
                active_migration: true,
            };
            let inactive_migration = MigrationInfo {
                backup_service_info: None,
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

    const BLOCK_HEIGHT: u64 = 6;
    const PORT_OVERRIDE: Option<u16> = None;
    const NUM_DOMAINS: usize = 1;
    pub(crate) fn make_resharing_contract_case(
        onboarding_node_p2p_public_key: VerifyingKey,
    ) -> ContractCase {
        let contract = ContractState::from_contract_state(
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
        let contract = ContractState::from_contract_state(
            &ProtocolContractState::Running(running_state.clone()),
            BLOCK_HEIGHT,
            PORT_OVERRIDE,
        )
        .unwrap();

        (
            ContractCase::new(contract, onboarding_node_p2p_public_key),
            running_state.keyset,
        )
    }
    pub(crate) fn make_initializing_contract_case(
        onboarding_node_p2p_public_key: VerifyingKey,
    ) -> ContractCase {
        let contract = ContractState::from_contract_state(
            &ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, 0).1),
            BLOCK_HEIGHT,
            PORT_OVERRIDE,
        )
        .unwrap();
        ContractCase::new(contract, onboarding_node_p2p_public_key)
    }
}
