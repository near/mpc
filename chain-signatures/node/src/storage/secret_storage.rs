use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::{GcpService, SecretResult};
use crate::storage::Options;
use crate::{gcp::SecretManagerService, protocol::state::PersistentNodeData};
use async_trait::async_trait;

use near_account_id::AccountId;

#[async_trait]
pub trait SecretNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()>;
    async fn load(&self) -> SecretResult<Option<PersistentNodeData>>;
}

#[derive(Default)]
struct MemoryNodeStorage {
    node_data: Option<PersistentNodeData>,
}

#[async_trait]
impl SecretNodeStorage for MemoryNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using MemoryNodeStorage");
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using MemoryNodeStorage");
        Ok(self.node_data.clone())
    }
}

struct SecretManagerNodeStorage {
    secret_manager: SecretManagerService,
    sk_share_secret_id: String,
}

impl SecretManagerNodeStorage {
    fn new(secret_manager: &SecretManagerService, sk_share_secret_id: String) -> Self {
        Self {
            secret_manager: secret_manager.clone(),
            sk_share_secret_id,
        }
    }
}

#[async_trait]
impl SecretNodeStorage for SecretManagerNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using SecretManagerNodeStorage");
        self.secret_manager
            .store_secret(&serde_json::to_vec(data)?, &self.sk_share_secret_id)
            .await?;
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using SecretManagerNodeStorage");
        let raw_data = self
            .secret_manager
            .load_secret(&self.sk_share_secret_id)
            .await?;
        match raw_data {
            Some(data) if data.len() > 1 => match serde_json::from_slice(&data) {
                Ok(persistent_node_data) => Ok(Some(persistent_node_data)),
                Err(err) => {
                    tracing::error!(%err, data_len = data.len(), "failed to convert stored data to key share, presuming it is missing");
                    Ok(None)
                }
            },
            _ => {
                tracing::error!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }
}

struct DiskNodeStorage {
    path: PathBuf,
}

impl DiskNodeStorage {
    pub fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }
}

#[async_trait]
impl SecretNodeStorage for DiskNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::info!("storing PersistentNodeData using DiskNodeStorage");
        let mut file = File::create(self.path.as_os_str()).await?;
        // Serialize the person object to JSON and convert directly to bytes
        let json_bytes = serde_json::to_vec(data)?;
        // Write the serialized JSON bytes to the file
        file.write_all(&json_bytes).await?;

        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using DiskNodeStorage");
        // Open the file asynchronously
        let file_res = File::open(self.path.as_os_str()).await;

        match file_res {
            Ok(mut file) => {
                let mut contents = Vec::new();
                // Read the contents of the file into the vector
                tracing::info!("loading PersistentNodeData using DiskNodeStorage: reading");
                file.read_to_end(&mut contents).await?;

                tracing::info!("loading PersistentNodeData using DiskNodeStorage: read done");
                // Deserialize the JSON content to a PersistentNodeData object
                let data: PersistentNodeData = serde_json::from_slice(&contents)?;

                Ok(Some(data))
            }
            _ => Ok(None),
        }
    }
}

pub type SecretNodeStorageBox = Box<dyn SecretNodeStorage + Send + Sync>;

pub fn init(
    gcp_service: Option<&GcpService>,
    opts: &Options,
    account_id: &AccountId,
) -> SecretNodeStorageBox {
    match gcp_service {
        Some(gcp) if opts.sk_share_secret_id.is_some() => {
            tracing::info!("using SecretManagerNodeStorage");
            Box::new(SecretManagerNodeStorage::new(
                &gcp.secret_manager.clone(),
                opts.clone().sk_share_secret_id.unwrap().clone(),
            )) as SecretNodeStorageBox
        }
        _ => {
            if let Some(sk_share_local_path) = &opts.sk_share_local_path {
                let path = format!("{sk_share_local_path}-{account_id}");
                tracing::info!("using DiskNodeStorage with path: {}", path);
                Box::new(DiskNodeStorage::new(&path)) as SecretNodeStorageBox
            } else {
                tracing::info!("using MemoryNodeStorage");
                Box::<MemoryNodeStorage>::default() as SecretNodeStorageBox
            }
        }
    }
}
