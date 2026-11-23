use crate::errors::Error;
use crate::tee::attested_service::AttestedService;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env, log, near};
use std::time::Duration;

#[near]
impl MpcContract {
    /// Votes to allow a backup service image hash. Once the threshold is reached, the backup
    /// service compose hashes are derived for it against every allowed backup service launcher.
    #[handle_result]
    pub fn vote_backup_service_code_hash(
        &mut self,
        code_hash: dtos::NodeImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_backup_service_code_hash: signer={}, code_hash={:?}",
            env::signer_account_id(),
            code_hash,
        );
        self.vote_image_hash(AttestedService::BackupService, code_hash)
    }

    /// Votes to allow a backup service launcher image hash. Once the threshold is reached, the
    /// backup service compose hashes are derived for it against every allowed backup service
    /// image hash.
    #[handle_result]
    pub fn vote_add_backup_service_launcher_hash(
        &mut self,
        launcher_hash: dtos::LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_add_backup_service_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.vote_launcher(
            AttestedService::BackupService,
            dtos::LauncherVoteAction::Add(launcher_hash),
        )
    }

    /// Votes to remove a backup service launcher image hash. Requires every participant's vote,
    /// since this invalidates the attestations of backup services running that launcher.
    #[handle_result]
    pub fn vote_remove_backup_service_launcher_hash(
        &mut self,
        launcher_hash: dtos::LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_backup_service_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.vote_launcher(
            AttestedService::BackupService,
            dtos::LauncherVoteAction::Remove(launcher_hash),
        )
    }

    /// Votes to allow an OS measurement set for backup services. Requires threshold votes.
    #[handle_result]
    pub fn vote_add_backup_service_os_measurement(
        &mut self,
        measurement: dtos::ExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_add_backup_service_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.vote_measurement(
            AttestedService::BackupService,
            dtos::MeasurementVoteAction::Add(measurement),
        )
    }

    /// Votes to remove an OS measurement set for backup services. Requires every participant's
    /// vote.
    #[handle_result]
    pub fn vote_remove_backup_service_os_measurement(
        &mut self,
        measurement: dtos::ExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_backup_service_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.vote_measurement(
            AttestedService::BackupService,
            dtos::MeasurementVoteAction::Remove(measurement),
        )
    }

    /// Private endpoint to drop backup service votes cast by non-participants after resharing.
    /// It runs in its own promise, apart from [`MpcContract::clean_tee_status`], so that the
    /// votes of each service get the whole gas budget.
    #[private]
    #[handle_result]
    pub fn clean_backup_service_tee_status(&mut self) -> Result<(), Error> {
        log!(
            "clean_backup_service_tee_status: signer={}",
            env::signer_account_id()
        );
        self.clean_non_participant_tee_votes(AttestedService::BackupService)
    }

    /// Returns the allowed backup service image hashes with their eviction expiry, newest first.
    /// The expiry depends on [`dtos::Config::tee_upgrade_deadline_duration_seconds`], as for
    /// MPC nodes.
    pub fn allowed_backup_service_code_hashes(&self) -> Vec<dtos::AllowedMpcDockerImageHash> {
        self.node_migrations
            .backup_service_tee_state
            .get_allowed_mpc_docker_images(Duration::from_secs(
                self.config.tee_upgrade_deadline_duration_seconds,
            ))
    }

    /// Returns the allowed backup service launcher compose hashes.
    pub fn allowed_backup_service_launcher_compose_hashes(
        &self,
    ) -> Vec<dtos::LauncherDockerComposeHash> {
        self.node_migrations
            .backup_service_tee_state
            .get_allowed_launcher_compose_hashes()
    }

    /// Returns the allowed backup service launcher image hashes.
    pub fn allowed_backup_service_launcher_image_hashes(&self) -> Vec<dtos::LauncherImageHash> {
        self.node_migrations
            .backup_service_tee_state
            .get_allowed_launcher_hashes()
    }

    /// Returns the OS measurement sets a backup service may run on.
    pub fn allowed_backup_service_os_measurements(&self) -> Vec<dtos::ExpectedMeasurements> {
        self.node_migrations
            .backup_service_tee_state
            .get_allowed_measurements()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::{
        MpcContract,
        api::test_utils::{participant_account_ids, setup_tee_test_contract},
        dto_mapping::IntoInterfaceType as _,
        errors::Error,
        primitives::thresholds::GovernanceThresholdParameters,
        state::ProtocolContractState,
        tee::{
            launcher_compose::LauncherCompose,
            test_utils::{
                Environment, MPC_NODE_COMPOSE, make_measurement, whitelist_dstack_measurements,
            },
        },
    };
    use mpc_attestation::attestation::default_measurements;
    use near_account_id::AccountId;
    use near_mpc_contract_interface::types as dtos;
    use rstest::{fixture, rstest};
    use std::{collections::BTreeMap, time::Duration};

    const IMAGE: dtos::NodeImageHash = dtos::NodeImageHash::new([1; 32]);
    const LAUNCHER: dtos::LauncherImageHash = dtos::LauncherImageHash::new([2; 32]);
    const OTHER_LAUNCHER: dtos::LauncherImageHash = dtos::LauncherImageHash::new([3; 32]);

    fn measurement() -> dtos::ExpectedMeasurements {
        make_measurement(1)
    }

    fn other_measurement() -> dtos::ExpectedMeasurements {
        make_measurement(2)
    }

    #[fixture]
    fn contract() -> MpcContract {
        setup_tee_test_contract(3, 2).0
    }

    #[derive(Debug, Default, PartialEq)]
    struct Allowlists {
        code_hashes: Vec<dtos::AllowedMpcDockerImageHash>,
        launcher_compose_hashes: Vec<dtos::LauncherDockerComposeHash>,
        launcher_image_hashes: Vec<dtos::LauncherImageHash>,
        os_measurements: Vec<dtos::ExpectedMeasurements>,
    }

    fn mpc_node_allowlists(contract: &MpcContract) -> Allowlists {
        Allowlists {
            code_hashes: contract.allowed_docker_image_hashes(),
            launcher_compose_hashes: contract.allowed_launcher_compose_hashes(),
            launcher_image_hashes: contract.allowed_launcher_image_hashes(),
            os_measurements: contract.allowed_os_measurements(),
        }
    }

    fn backup_service_allowlists(contract: &MpcContract) -> Allowlists {
        Allowlists {
            code_hashes: contract.allowed_backup_service_code_hashes(),
            launcher_compose_hashes: contract.allowed_backup_service_launcher_compose_hashes(),
            launcher_image_hashes: contract.allowed_backup_service_launcher_image_hashes(),
            os_measurements: contract.allowed_backup_service_os_measurements(),
        }
    }

    type Vote = fn(&mut MpcContract) -> Result<(), Error>;

    fn vote_as(contract: &mut MpcContract, account_id: &AccountId, vote: Vote) {
        Environment::new(None, Some(account_id.clone()), None);
        vote(contract).unwrap();
    }

    fn vote_as_every_participant(contract: &mut MpcContract, vote: Vote) {
        for account_id in participant_account_ids(contract) {
            vote_as(contract, &account_id, vote);
        }
    }

    #[rstest]
    fn allowed_backup_service_views__should_list_the_backup_service_tee_state_allowlists(
        mut contract: MpcContract,
    ) {
        // Given
        whitelist_dstack_measurements(
            &mut contract.node_migrations.backup_service_tee_state,
            IMAGE,
            LAUNCHER,
            default_measurements(),
            None,
        );

        // When
        let allowlists = backup_service_allowlists(&contract);

        // Then
        assert_eq!(
            allowlists,
            Allowlists {
                code_hashes: vec![dtos::AllowedMpcDockerImageHash {
                    image_hash: IMAGE,
                    expiry_timestamp_seconds: None,
                }],
                launcher_compose_hashes: vec![MPC_NODE_COMPOSE.hash(&LAUNCHER, &IMAGE)],
                launcher_image_hashes: vec![LAUNCHER],
                os_measurements: vec![default_measurements().into_dto_type()],
            }
        );
    }

    #[rstest]
    #[case::code_hash(
        |contract: &mut MpcContract| contract.vote_backup_service_code_hash(IMAGE),
        Allowlists {
            code_hashes: vec![dtos::AllowedMpcDockerImageHash {
                image_hash: IMAGE,
                expiry_timestamp_seconds: None,
            }],
            ..Default::default()
        },
    )]
    #[case::launcher(
        |contract: &mut MpcContract| contract.vote_add_backup_service_launcher_hash(LAUNCHER),
        Allowlists {
            launcher_image_hashes: vec![LAUNCHER],
            ..Default::default()
        },
    )]
    #[case::os_measurement(
        |contract: &mut MpcContract| contract.vote_add_backup_service_os_measurement(measurement()),
        Allowlists {
            os_measurements: vec![measurement()],
            ..Default::default()
        },
    )]
    fn backup_service_votes__should_add_only_to_the_backup_service_allowlists(
        mut contract: MpcContract,
        #[case] vote: Vote,
        #[case] expected_backup_service_allowlists: Allowlists,
    ) {
        // Given
        let mpc_node_allowlists_before = mpc_node_allowlists(&contract);

        // When
        vote_as_every_participant(&mut contract, vote);

        // Then
        assert_eq!(
            (
                mpc_node_allowlists(&contract),
                backup_service_allowlists(&contract)
            ),
            (
                mpc_node_allowlists_before,
                expected_backup_service_allowlists
            )
        );
    }

    #[rstest]
    #[case::launcher(
        |contract: &mut MpcContract| contract.vote_remove_backup_service_launcher_hash(LAUNCHER),
        Allowlists {
            launcher_image_hashes: vec![OTHER_LAUNCHER],
            os_measurements: vec![measurement(), other_measurement()],
            ..Default::default()
        },
    )]
    #[case::os_measurement(
        |contract: &mut MpcContract| {
            contract.vote_remove_backup_service_os_measurement(measurement())
        },
        Allowlists {
            launcher_image_hashes: vec![LAUNCHER, OTHER_LAUNCHER],
            os_measurements: vec![other_measurement()],
            ..Default::default()
        },
    )]
    fn backup_service_votes__should_remove_only_from_the_backup_service_allowlists(
        mut contract: MpcContract,
        #[case] vote: Vote,
        #[case] expected_backup_service_allowlists: Allowlists,
    ) {
        // Given
        for tee_state in [
            &mut contract.tee_state,
            &mut contract.node_migrations.backup_service_tee_state,
        ] {
            for launcher in [LAUNCHER, OTHER_LAUNCHER] {
                tee_state.add_launcher_image(
                    launcher,
                    MPC_NODE_COMPOSE,
                    Duration::MAX,
                    Duration::MAX,
                );
            }
            for measurement in [measurement(), other_measurement()] {
                tee_state.add_measurement(measurement);
            }
        }
        let mpc_node_allowlists_before = mpc_node_allowlists(&contract);

        // When
        vote_as_every_participant(&mut contract, vote);

        // Then
        assert_eq!(
            (
                mpc_node_allowlists(&contract),
                backup_service_allowlists(&contract)
            ),
            (
                mpc_node_allowlists_before,
                expected_backup_service_allowlists
            )
        );
    }

    #[rstest]
    fn backup_service_votes__should_derive_compose_hashes_from_the_backup_service_template(
        mut contract: MpcContract,
    ) {
        // Given
        vote_as_every_participant(&mut contract, |contract| {
            contract.vote_add_backup_service_launcher_hash(LAUNCHER)
        });

        // When
        vote_as_every_participant(&mut contract, |contract| {
            contract.vote_backup_service_code_hash(IMAGE)
        });
        vote_as_every_participant(&mut contract, |contract| {
            contract.vote_add_backup_service_launcher_hash(OTHER_LAUNCHER)
        });

        // Then
        let compose = LauncherCompose::backup_service(contract.genesis_hash);
        assert_eq!(
            contract.allowed_backup_service_launcher_compose_hashes(),
            vec![
                compose.hash(&LAUNCHER, &IMAGE),
                compose.hash(&OTHER_LAUNCHER, &IMAGE),
            ]
        );
    }

    #[rstest]
    fn clean_backup_service_tee_status__should_drop_departed_participants_votes(
        mut contract: MpcContract,
    ) {
        // Given
        let departed = participant_account_ids(&contract)[0].clone();
        let votes: [Vote; 3] = [
            |contract| contract.vote_backup_service_code_hash(IMAGE),
            |contract| contract.vote_add_backup_service_launcher_hash(LAUNCHER),
            |contract| contract.vote_add_backup_service_os_measurement(measurement()),
        ];
        for vote in votes {
            vote_as(&mut contract, &departed, vote);
        }
        let ProtocolContractState::Running(state) = &mut contract.protocol_state else {
            panic!("expected Running");
        };
        let participants = state.parameters.participants();
        let remaining = participants.subset(1..participants.len());
        state.parameters =
            GovernanceThresholdParameters::new(remaining, state.parameters.threshold()).unwrap();

        // When
        contract.clean_backup_service_tee_status().unwrap();

        // Then
        let backup_service_tee_state = &contract.node_migrations.backup_service_tee_state;
        assert_eq!(
            [
                backup_service_tee_state.votes.all(),
                backup_service_tee_state.launcher_votes.all(),
                backup_service_tee_state.measurement_votes.all(),
            ],
            [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()]
        );
    }
}
