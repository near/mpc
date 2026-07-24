use std::path::{Path, PathBuf};

use near_mpc_contract_interface::types::{
    Keyset, ProtocolContractState, ProtocolContractStateCompat,
};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::ports::ContractStateReader;

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

impl ContractStateReader for ContractStateFixture {
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

        // TODO(XXXX): Switch to canonical after upgrade 3.14.0
        // `state()` still emits the pre-3903 field names; deserialize the compat
        // shape and convert to the canonical DTO.
        let state: ProtocolContractStateCompat =
            serde_json::from_slice(&buffer).map_err(Error::JsonDeserialization)?;
        Ok(state.into())
    }
}

pub fn get_keyset_from_contract_state(
    contract_state: &ProtocolContractState,
) -> Result<Keyset, Error> {
    match contract_state {
        ProtocolContractState::NotInitialized => {
            Err(Error::IncorrectContractState("NotInitialized".to_string()))
        }
        ProtocolContractState::Resharing(_) => {
            Err(Error::IncorrectContractState("Resharing".to_string()))
        }
        ProtocolContractState::Initializing(state) => Ok(Keyset {
            epoch_id: state.epoch_id,
            domains: state.generated_keys.clone(),
        }),
        ProtocolContractState::Running(state) => Ok(state.keyset.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use near_mpc_contract_interface::types::{GovernanceThreshold, ProtocolContractState};

    use crate::{
        adapters::contract_state_fixture::ContractStateFixture, ports::ContractStateReader,
    };

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
        assert_eq!(
            state.parameters.governance_threshold,
            GovernanceThreshold::new(7)
        );
        assert_eq!(state.domains.domains.len(), 2);
    }
}
