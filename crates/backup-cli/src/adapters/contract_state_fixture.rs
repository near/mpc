use std::path::{Path, PathBuf};

use near_mpc_contract_interface::types::Keyset;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::ports::ReadCurrentKeyset;

const CURRENT_KEYSET_FILENAME: &str = "current_keyset.json";

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
    current_keyset_path: PathBuf,
}

impl ContractStateFixture {
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        let current_keyset_path = storage_path.as_ref().join(CURRENT_KEYSET_FILENAME);
        Self {
            current_keyset_path,
        }
    }
}

impl ReadCurrentKeyset for ContractStateFixture {
    type Error = Error;

    async fn current_keyset(&self) -> Result<Option<Keyset>, Self::Error> {
        let mut destination = File::open(self.current_keyset_path.as_path())
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
#[expect(non_snake_case)]
mod tests {
    use std::path::PathBuf;

    use near_mpc_contract_interface::types::EpochId;

    use crate::{adapters::contract_state_fixture::ContractStateFixture, ports::ReadCurrentKeyset};

    pub const TEST_CONTRACT_STATE_PATH: &str = "assets/";
    #[tokio::test]
    async fn current_keyset__should_read_the_saved_view_output() {
        // Given
        let storage_path = PathBuf::from(TEST_CONTRACT_STATE_PATH);
        let contract_interface = ContractStateFixture::new(storage_path);

        // When
        let current_keyset = contract_interface.current_keyset().await.unwrap();

        // Then
        let keyset = current_keyset.unwrap();
        assert_eq!(keyset.epoch_id, EpochId::new(4));
        assert_eq!(keyset.domains.len(), 2);
    }
}
