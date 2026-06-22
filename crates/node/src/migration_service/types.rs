use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{BackupServiceInfo, DestinationNodeInfo};
use near_mpc_crypto_types::Keyset;
use serde::Serialize;

use crate::{
    config::{MpcConfig, NodeStatus, ParticipantStatus},
    indexer::{
        migrations::ContractMigrationInfo,
        participants::{ContractInitializingState, ContractRunningState, ContractState},
    },
};

pub struct NodeBackupServiceInfo {
    pub p2p_key: VerifyingKey,
}

impl NodeBackupServiceInfo {
    pub fn from_contract(info: BackupServiceInfo) -> anyhow::Result<Self> {
        let p2p_key = match ed25519_dalek::VerifyingKey::try_from(&info.public_key) {
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

/// Unified classification of "what should this node be doing right now?"
///
/// Replaces the previous `OnboardingJob` (3 arms: Done / Onboard / Wait)
/// and folds in the per-state dispatch that used to live inside
/// `Coordinator::run` (Initializing vs Running, with the in-line
/// participant-check that returned `MpcJobResult::HaltUntilInterrupted`
/// when the node was not in the contract's participant list).
///
/// The active-participant arms carry their pre-derived `MpcConfig`, so
/// the worker functions in `coordinator.rs` no longer re-derive it (and
/// no longer need the defensive `HaltUntilInterrupted` short-circuit).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum NodeJob {
    /// Not an active participant; the migration record says we should
    /// onboard with this keyset.
    Onboard(Keyset),
    /// Nothing actionable until contract or migration state changes.
    WaitForStateChange,
    /// Active participant in an Initializing contract — drive key generation.
    Initialize {
        state: ContractInitializingState,
        mpc_config: MpcConfig,
    },
    /// Active participant in a Running contract (with or without resharing
    /// in-flight — the resharing sub-mode is encoded in
    /// `state.resharing_state`).
    Run {
        state: ContractRunningState,
        mpc_config: MpcConfig,
    },
}

impl NodeJob {
    /// Constructs the current job for this node from contract + migration state.
    ///
    /// Active-participant paths derive `MpcConfig` once here, so callers
    /// never repeat the participant check. If the contract reports the
    /// node as Active but `MpcConfig::from_participants_with_near_account_id`
    /// returns `None` (e.g. participants list is being mutated mid-flight),
    /// we conservatively return `WaitForStateChange` — same defensive
    /// posture as the deleted in-line check.
    pub fn new(
        my_migration_info: MigrationInfo,
        contract: ContractState,
        my_near_account_id: &AccountId,
        tls_public_key: &VerifyingKey,
    ) -> Self {
        match contract.node_status(my_near_account_id, tls_public_key) {
            ParticipantStatus::Inactive => NodeJob::WaitForStateChange,
            ParticipantStatus::Active(NodeStatus::Idle) => {
                if my_migration_info.active_migration {
                    match contract {
                        ContractState::Running(running_state)
                            if running_state.resharing_state.is_none() =>
                        {
                            NodeJob::Onboard(running_state.keyset)
                        }
                        _ => NodeJob::WaitForStateChange,
                    }
                } else {
                    NodeJob::WaitForStateChange
                }
            }
            ParticipantStatus::Active(NodeStatus::Active) => match contract {
                ContractState::Invalid => NodeJob::WaitForStateChange,
                ContractState::Initializing(state) => {
                    let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
                        state.participants.clone(),
                        my_near_account_id,
                        tls_public_key,
                    ) else {
                        return NodeJob::WaitForStateChange;
                    };
                    NodeJob::Initialize { state, mpc_config }
                }
                ContractState::Running(state) => {
                    // During resharing, the mpc_config uses the *new* participants
                    // (post-resharing set) — mirrors the participants_config
                    // derivation that used to live inside `run_mpc`. Outside of
                    // resharing, it uses the current running participants.
                    let participants_for_config = match &state.resharing_state {
                        Some(resharing_state) => resharing_state.new_participants.clone(),
                        None => state.participants.clone(),
                    };
                    let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
                        participants_for_config,
                        my_near_account_id,
                        tls_public_key,
                    ) else {
                        return NodeJob::WaitForStateChange;
                    };
                    NodeJob::Run { state, mpc_config }
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
            ed25519_dalek::VerifyingKey::try_from(&info.destination_node_info.tls_public_key)
                .inspect_err(|_| tracing::warn!(target: "Migration Service", "Error parsing public key from chain."))
                .is_ok_and(|key| key == *my_p2p_public_key)
        })
        .unwrap_or(false)
}

#[cfg(test)]
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
        tests::dto_conversions::keyset_to_dto,
    };

    use super::{BackupServiceInfo, DestinationNodeInfo, MigrationInfo, NodeJob};

    #[test]
    fn test_migration_get_pk_backup_service() {
        let empty = MigrationInfo {
            backup_service_info: None,
            active_migration: true,
        };
        assert!(empty.get_pk_backup_service().is_none());

        let public_key = bogus_ed25519_public_key();
        let pk_converted: ed25519_dalek::VerifyingKey = (&public_key).try_into().unwrap();
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
        let p2p_public_key =
            ed25519_dalek::VerifyingKey::try_from(&bogus_ed25519_public_key()).unwrap();

        let res = MigrationInfo::from_contract_state(&account_id, &p2p_public_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, None);
    }

    #[test]
    fn test_migration_status_constructor_populated() {
        let mut state = ContractMigrationInfo::new();
        let (account_id_0, participant_info_0) = gen_participant(0);
        let (account_id_1, _) = gen_participant(1);
        let signer_account_pk = bogus_ed25519_public_key();
        let participant_tls_public_key = participant_info_0.tls_public_key.clone();
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: signer_account_pk.clone(),
            destination_node_info: participant_info_0.clone().into(),
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
            ed25519_dalek::VerifyingKey::try_from(&participant_tls_public_key).unwrap();
        let non_participating_key =
            ed25519_dalek::VerifyingKey::try_from(&signer_account_pk).unwrap();

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

    struct NodeJobConstructorTestCase {
        case: String,
        migration_info: MigrationInfo,
        contract: ContractState,
        node_id: TestNodeId,
        /// Predicate over the resulting `NodeJob`. We use a predicate
        /// rather than `assert_eq!` because the active-participant arms
        /// (`Initialize`, `Run`) carry an `MpcConfig` payload — reconstructing
        /// the exact `MpcConfig` in the test would duplicate the classifier
        /// itself. Variant-shape assertions are sufficient for these
        /// classification tests; the payload's correctness is exercised by
        /// the coordinator's per-arm tests.
        expected: fn(&NodeJob) -> bool,
    }

    impl NodeJobConstructorTestCase {
        fn run(self) {
            let job = NodeJob::new(
                self.migration_info,
                self.contract,
                &self.node_id.account_id,
                &self.node_id.p2p_public_key,
            );
            assert!(
                (self.expected)(&job),
                "case: {}, got: {:?}",
                self.case,
                job
            );
        }
    }

    #[test]
    fn test_node_job_participants() {
        let setup = NodeJobConstructorTestSetup::new();
        // Active participant in Initializing -> NodeJob::Initialize{..}
        NodeJobConstructorTestCase {
            case: "Initializing Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.participant_node.clone(),
            expected: |j| matches!(j, NodeJob::Initialize { .. }),
        }
        .run();

        // Active participant in Running (with resharing) -> NodeJob::Run{..}
        NodeJobConstructorTestCase {
            case: "Resharing Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.participant_node.clone(),
            expected: |j| matches!(j, NodeJob::Run { .. }),
        }
        .run();

        // Active participant in Running (no resharing) -> NodeJob::Run{..}
        NodeJobConstructorTestCase {
            case: "Running Participant".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.running.participant_node.clone(),
            expected: |j| matches!(j, NodeJob::Run { .. }),
        }
        .run();
    }

    #[test]
    fn test_node_job_inactive() {
        let setup = NodeJobConstructorTestSetup::new();
        // An inactive migration for an onboarding participant should always result in a "wait"
        // initializing
        NodeJobConstructorTestCase {
            case: "Initializing inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.onboarding_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
        // resharing
        NodeJobConstructorTestCase {
            case: "Resharing inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.onboarding_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
        // running
        NodeJobConstructorTestCase {
            case: "Running inactive".into(),
            migration_info: setup.inactive_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.running.onboarding_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
    }
    #[test]
    fn test_node_job_active() {
        let setup = NodeJobConstructorTestSetup::new();
        // Running with active migration and an onboarding participant result in onboarding.
        // Asserted inline because the keyset comparison is value-dependent and the
        // NodeJobConstructorTestCase predicate is `fn`, not a capturing closure.
        let job = NodeJob::new(
            setup.active_migration.clone(),
            setup.running.contract.clone(),
            &setup.running.onboarding_node.account_id,
            &setup.running.onboarding_node.p2p_public_key,
        );
        match job {
            NodeJob::Onboard(k) => assert_eq!(k, setup.running_keyset),
            other => panic!("expected Onboard, got {:?}", other),
        }

        // but not when we have an ongoing key generation or resharing
        // initializing
        NodeJobConstructorTestCase {
            case: "Initializing active".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.initializing.onboarding_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
        // resharing
        NodeJobConstructorTestCase {
            case: "Resharing active".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.resharing.onboarding_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
    }

    #[test]
    fn test_node_job_non_participant() {
        let setup = NodeJobConstructorTestSetup::new();
        // a non-participant must always wait for a state change
        // initializing
        NodeJobConstructorTestCase {
            case: "Non-participant initializing".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.initializing.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
        // resharing
        NodeJobConstructorTestCase {
            case: "Non-participant resharing".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.resharing.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
        // running
        NodeJobConstructorTestCase {
            case: "Non-participant running".into(),
            migration_info: setup.active_migration.clone(),
            contract: setup.running.contract.clone(),
            node_id: setup.non_participant.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
    }
    #[test]
    fn test_node_job_invalid() {
        let setup = NodeJobConstructorTestSetup::new();
        // invalid must result in Wait:
        NodeJobConstructorTestCase {
            case: "Invalid".into(),
            migration_info: setup.active_migration.clone(),
            contract: ContractState::Invalid,
            node_id: setup.running.participant_node.clone(),
            expected: |j| matches!(j, NodeJob::WaitForStateChange),
        }
        .run();
    }

    impl NodeJobConstructorTestSetup {
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

    struct NodeJobConstructorTestSetup {
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
        ContractState::from_contract_state(&dto, height, port_override)
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
            keyset_to_dto(&running_state.keyset),
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
