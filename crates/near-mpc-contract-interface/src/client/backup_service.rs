use near_contract_transport::{CallContract, FunctionCallArgs, ViewArgs, ViewCall, ViewContract};

use crate::{
    call_args::{VoteBackupServiceCodeHashArgs, VoteLauncherHashArgs, VoteOsMeasurementArgs},
    client::{MAX_GAS, MpcContractHandle, MpcContractHandleError},
    method_names::{
        ALLOWED_BACKUP_SERVICE_CODE_HASHES, ALLOWED_BACKUP_SERVICE_LAUNCHER_COMPOSE_HASHES,
        ALLOWED_BACKUP_SERVICE_LAUNCHER_IMAGE_HASHES, ALLOWED_BACKUP_SERVICE_OS_MEASUREMENTS,
        CLEAN_BACKUP_SERVICE_TEE_STATUS, VOTE_ADD_BACKUP_SERVICE_LAUNCHER_HASH,
        VOTE_ADD_BACKUP_SERVICE_OS_MEASUREMENT, VOTE_BACKUP_SERVICE_CODE_HASH,
        VOTE_REMOVE_BACKUP_SERVICE_LAUNCHER_HASH, VOTE_REMOVE_BACKUP_SERVICE_OS_MEASUREMENT,
    },
    types::{
        AllowedMpcDockerImageHash, ExpectedMeasurements, LauncherDockerComposeHash,
        LauncherImageHash, NodeImageHash,
    },
};

impl<C: CallContract> MpcContractHandle<C> {
    pub async fn vote_backup_service_code_hash(
        &self,
        code_hash: NodeImageHash,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteBackupServiceCodeHashArgs::new(code_hash))?;
        self.call(FunctionCallArgs::no_deposit(
            VOTE_BACKUP_SERVICE_CODE_HASH,
            args,
            MAX_GAS,
        ))
        .await
    }

    pub async fn vote_add_backup_service_launcher_hash(
        &self,
        launcher_hash: LauncherImageHash,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteLauncherHashArgs::new(launcher_hash))?;
        self.call(FunctionCallArgs::no_deposit(
            VOTE_ADD_BACKUP_SERVICE_LAUNCHER_HASH,
            args,
            MAX_GAS,
        ))
        .await
    }

    pub async fn vote_remove_backup_service_launcher_hash(
        &self,
        launcher_hash: LauncherImageHash,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteLauncherHashArgs::new(launcher_hash))?;
        self.call(FunctionCallArgs::no_deposit(
            VOTE_REMOVE_BACKUP_SERVICE_LAUNCHER_HASH,
            args,
            MAX_GAS,
        ))
        .await
    }

    pub async fn vote_add_backup_service_os_measurement(
        &self,
        measurement: ExpectedMeasurements,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteOsMeasurementArgs::new(measurement))?;
        self.call(FunctionCallArgs::no_deposit(
            VOTE_ADD_BACKUP_SERVICE_OS_MEASUREMENT,
            args,
            MAX_GAS,
        ))
        .await
    }

    pub async fn vote_remove_backup_service_os_measurement(
        &self,
        measurement: ExpectedMeasurements,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteOsMeasurementArgs::new(measurement))?;
        self.call(FunctionCallArgs::no_deposit(
            VOTE_REMOVE_BACKUP_SERVICE_OS_MEASUREMENT,
            args,
            MAX_GAS,
        ))
        .await
    }

    pub async fn clean_backup_service_tee_status(
        &self,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        self.call(FunctionCallArgs::no_deposit(
            CLEAN_BACKUP_SERVICE_TEE_STATUS,
            b"{}".to_vec(),
            MAX_GAS,
        ))
        .await
    }
}

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
