use std::path::{Path, PathBuf};

use near_account_id::AccountId;
use near_contract_transport::{ObservedState, ViewArgs, ViewContract};
use near_mpc_contract_interface::client::MpcContractHandle;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

const CONTRACT_STATE_FILENAME: &str = "contract_state.json";

/// A fixture answers from its file, so which account it is asked about is
/// immaterial; a handle still needs one.
const FIXTURE_CONTRACT: &str = "fixture.near";

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("failed to open file: {0}")]
    OpenFile(String),

    #[error("could not read from file: {0}")]
    Read(String),
}

#[derive(Clone)]
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

    pub fn handle(self) -> MpcContractHandle<Self> {
        MpcContractHandle::new(
            self,
            FIXTURE_CONTRACT.parse().expect("a valid account id"),
        )
    }
}

/// Answers every view method with the fixture file, which only holds the
/// contract state. Height is reported as `0`: a file has no block.
impl ViewContract for ContractStateFixture {
    type Error = Error;

    async fn view_contract(
        &self,
        _contract_id: &AccountId,
        _view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        let mut destination = File::open(self.contract_state_path.as_path())
            .await
            .map_err(|err| Error::OpenFile(err.to_string()))?;
        let mut buffer = Vec::new();
        destination
            .read_to_end(&mut buffer)
            .await
            .map_err(|err| Error::Read(err.to_string()))?;

        Ok(ObservedState {
            observed_at: 0.into(),
            value: buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use near_mpc_contract_interface::types::{GovernanceThreshold, ProtocolContractState};

    use crate::adapters::contract_state_fixture::ContractStateFixture;

    pub const TEST_CONTRACT_STATE_PATH: &str = "assets/";
    #[tokio::test]
    async fn test_get_contract_state() {
        // Given
        let storage_path = PathBuf::from(TEST_CONTRACT_STATE_PATH);
        let contract_interface = ContractStateFixture::new(storage_path).handle();

        // When
        let contract_state = contract_interface.state().await.unwrap().value;

        // Then
        let ProtocolContractState::Running(state) = &contract_state else {
            panic!("expected Running state, got {contract_state:?}");
        };
        assert_eq!(state.parameters.threshold, GovernanceThreshold::new(7));
        assert_eq!(state.domains.domains.len(), 2);
    }
}
