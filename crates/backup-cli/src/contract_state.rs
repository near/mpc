use std::path::Path;

use mpc_contract::state::ProtocolContractState;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

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

pub async fn read_contract_state(
    storage_path: impl AsRef<Path>,
) -> Result<ProtocolContractState, Error> {
    let file_path = storage_path.as_ref().join(CONTRACT_STATE_FILENAME);
    let mut destination = File::open(file_path).await.map_err(Error::OpenFile)?;
    let mut buffer = Vec::new();
    destination
        .read_to_end(&mut buffer)
        .await
        .map_err(Error::Read)?;

    serde_json::from_slice(&buffer).map_err(Error::JsonDeserialization)
}
