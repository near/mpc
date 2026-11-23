use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types as dtos;
use near_sdk::near;
use std::time::Duration;

#[near]
impl MpcContract {
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
        api::test_utils::setup_tee_test_contract,
        dto_mapping::IntoInterfaceType as _,
        tee::test_utils::{
            MPC_NODE_COMPOSE, dummy_code_hash, dummy_launcher_hash, whitelist_dstack_measurements,
        },
    };
    use mpc_attestation::attestation::default_measurements;
    use near_mpc_contract_interface::types as dtos;

    #[test]
    fn allowed_backup_service_views__should_list_the_backup_service_tee_state_allowlists() {
        // Given
        let (mut contract, _, _) = setup_tee_test_contract(3, 2);
        let image = dummy_code_hash(1);
        let launcher = dummy_launcher_hash(1);
        whitelist_dstack_measurements(
            &mut contract.node_migrations.backup_service_tee_state,
            image,
            launcher,
            default_measurements(),
            None,
        );

        // When
        let allowlists = (
            contract.allowed_backup_service_code_hashes(),
            contract.allowed_backup_service_launcher_compose_hashes(),
            contract.allowed_backup_service_launcher_image_hashes(),
            contract.allowed_backup_service_os_measurements(),
        );

        // Then
        assert_eq!(
            allowlists,
            (
                vec![dtos::AllowedMpcDockerImageHash {
                    image_hash: image,
                    expiry_timestamp_seconds: None,
                }],
                vec![MPC_NODE_COMPOSE.hash(&launcher, &image)],
                vec![launcher],
                vec![default_measurements().into_dto_type()],
            )
        );
    }
}
