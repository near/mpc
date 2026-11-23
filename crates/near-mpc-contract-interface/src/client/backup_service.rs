use near_contract_transport::{ViewArgs, ViewCall, ViewContract};

use crate::{
    client::MpcContractHandle,
    method_names::{
        ALLOWED_BACKUP_SERVICE_CODE_HASHES, ALLOWED_BACKUP_SERVICE_LAUNCHER_COMPOSE_HASHES,
        ALLOWED_BACKUP_SERVICE_LAUNCHER_IMAGE_HASHES, ALLOWED_BACKUP_SERVICE_OS_MEASUREMENTS,
    },
    types::{
        AllowedMpcDockerImageHash, ExpectedMeasurements, LauncherDockerComposeHash,
        LauncherImageHash,
    },
};

impl<C: ViewContract + Clone> MpcContractHandle<C> {
    pub fn allowed_backup_service_code_hashes(
        &self,
    ) -> ViewCall<C, Vec<AllowedMpcDockerImageHash>> {
        self.view(ViewArgs::no_args(ALLOWED_BACKUP_SERVICE_CODE_HASHES))
    }

    pub fn allowed_backup_service_launcher_compose_hashes(
        &self,
    ) -> ViewCall<C, Vec<LauncherDockerComposeHash>> {
        self.view(ViewArgs::no_args(
            ALLOWED_BACKUP_SERVICE_LAUNCHER_COMPOSE_HASHES,
        ))
    }

    pub fn allowed_backup_service_launcher_image_hashes(
        &self,
    ) -> ViewCall<C, Vec<LauncherImageHash>> {
        self.view(ViewArgs::no_args(
            ALLOWED_BACKUP_SERVICE_LAUNCHER_IMAGE_HASHES,
        ))
    }

    pub fn allowed_backup_service_os_measurements(&self) -> ViewCall<C, Vec<ExpectedMeasurements>> {
        self.view(ViewArgs::no_args(ALLOWED_BACKUP_SERVICE_OS_MEASUREMENTS))
    }
}
