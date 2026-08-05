use std::path::{Path, PathBuf};

use near_mpc_contract_interface::types::ProtocolContractState;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::ports::ReadContractState;

const CONTRACT_STATE_FILENAME: &str = "contract_state.json";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to open file: {0}")]
    OpenFile(tokio::io::Error),

    #[error("could not read from file: {0}")]
    Read(tokio::io::Error),

    #[error("failed to deserialize secrets")]
    JsonDeserialization(serde_json::Error),
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

impl ReadContractState for ContractStateFixture {
    type Error = Error;

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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use near_mpc_contract_interface::types::{GovernanceThreshold, ProtocolContractState};

    use crate::{adapters::contract_state_fixture::ContractStateFixture, ports::ReadContractState};

    pub const TEST_CONTRACT_STATE_PATH: &str = "assets/";
    #[tokio::test]
    async fn test_get_contract_state() {
        // Given
        let storage_path = PathBuf::from(TEST_CONTRACT_STATE_PATH);
        let contract_interface = ContractStateFixture::new(storage_path);

        // When
        let contract_state = contract_interface.get_contract_state().await.unwrap();

        // Then
        let ProtocolContractState::Running(state) = &contract_state else {
            panic!("expected Running state, got {contract_state:?}");
        };
        assert_eq!(state.parameters.threshold, GovernanceThreshold::new(7));
        assert_eq!(state.domains.domains.len(), 2);
    }
}
