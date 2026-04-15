use std::path::{Path, PathBuf};

use mpc_node::primitives::{KeyForDomain, Keyset};
use near_mpc_contract_interface::types::ProtocolContractState;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use near_mpc_contract_interface::types as dtos;

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

        serde_json::from_slice(&buffer).map_err(Error::JsonDeserialization)
    }
}

pub fn get_keyset_from_contract_state(
    contract_state: &dtos::ProtocolContractState,
) -> Result<Keyset, Error> {
    match contract_state {
        ProtocolContractState::NotInitialized | ProtocolContractState::Resharing(_) => Err(
            Error::IncorrectContractState("not initialized or resharing".to_string()),
        ),
        ProtocolContractState::Initializing(state) => {
            let keys: Result<Vec<KeyForDomain>, _> = state
                .generated_keys
                .iter()
                .cloned()
                .map(TryFrom::try_from)
                .collect();
            let keys =
                keys.map_err(|e: anyhow::Error| Error::IncorrectContractState(e.to_string()))?;
            Ok(Keyset::new(state.epoch_id.into(), keys))
        }
        ProtocolContractState::Running(state) => state
            .keyset
            .clone()
            .try_into()
            .map_err(|e: anyhow::Error| Error::IncorrectContractState(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use near_mpc_contract_interface::types::{ProtocolContractState, Threshold};

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
        let ProtocolContractState::Running(running) = &contract_state else {
            panic!("expected Running state, got {:?}", contract_state);
        };
        assert_eq!(running.parameters.threshold, Threshold(7));
        assert_eq!(running.domains.domains.len(), 2);
    }
}
