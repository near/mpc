use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
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
}

pub struct SimpleContractInterface {
    contract_state_path: PathBuf,
}

impl SimpleContractInterface {
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        let contract_state_path = storage_path.as_ref().join(CONTRACT_STATE_FILENAME);
        Self {
            contract_state_path,
        }
    }
}

impl ContractInterface for SimpleContractInterface {
    type Error = Error;

    async fn register_backup_data(&self, _public_key: &VerifyingKey) -> Result<(), Self::Error> {
        Ok(())
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
