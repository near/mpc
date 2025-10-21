use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use mpc_contract::primitives::key_state::Keyset;
use mpc_contract::state::ProtocolContractState;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::ports::ContractInterface;

const CONTRACT_STATE_FILENAME: &str = "contract_state.json";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to open file: {0}")]
    OpenFile(tokio::io::Error),

    #[error("could not read from file: {0}")]
    Read(tokio::io::Error),

    #[error("failed to deserialize secrets")]
    JsonDeserialization(serde_json::Error),

    #[error("incorrect contract state: {0}")]
    IncorrectContractState(String),
}

pub struct ContractStateFixture {
    contract_state_path: PathBuf,
}

impl ContractStateFixture {
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        let contract_state_path = storage_path.as_ref().join(CONTRACT_STATE_FILENAME);
        Self {
            contract_state_path,
        }
    }
}

impl ContractInterface for ContractStateFixture {
    type Error = Error;

    async fn register_backup_data(&self, _public_key: &VerifyingKey) -> Result<(), Self::Error> {
        // TODO(https://github.com/near/mpc/issues/1290)
        unimplemented!()
    }

    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        let mut destination = File::open(self.contract_state_path.as_path())
            .await
            .map_err(Error::OpenFile)?;
        let mut buffer = Vec::new();
        destination
            .read_to_end(&mut buffer)
            .await
            .map_err(Error::Read)?;

        serde_json::from_slice(&buffer).map_err(Error::JsonDeserialization)
    }
}

pub fn get_keyset_from_contract_state(
    contract_state: &ProtocolContractState,
) -> Result<Keyset, Error> {
    match contract_state {
        ProtocolContractState::NotInitialized | ProtocolContractState::Resharing(_) => Err(
            Error::IncorrectContractState(contract_state.name().to_string()),
        ),
        ProtocolContractState::Initializing(state) => {
            Ok(Keyset::new(state.epoch_id, state.generated_keys.clone()))
        }
        ProtocolContractState::Running(state) => Ok(state.keyset.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mpc_contract::primitives::thresholds::Threshold;

    use crate::{adapters::contract_interface::ContractStateFixture, ports::ContractInterface};

    pub const TEST_CONTRACT_STATE_PATH: &str = "assets/";
    #[tokio::test]
    async fn test_get_contract_state() {
        // Given
        let storage_path = PathBuf::from(TEST_CONTRACT_STATE_PATH);
        let contract_interface = ContractStateFixture::new(storage_path);

        // When
        let contract_state = contract_interface.get_contract_state().await.unwrap();

        // Then
        assert_eq!(contract_state.name(), "Running");
        assert_eq!(contract_state.threshold().unwrap(), Threshold::new(7));
        assert_eq!(contract_state.domain_registry().unwrap().domains().len(), 2);
    }
}
