pub mod gcp;
pub mod local;
mod migration;

use serde::{Deserialize, Serialize};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};


/// The root keyshare data along with an epoch. The epoch is incremented for each key resharing.
/// This structure is used in context, where we should have all key shares present (e.g. "Running" state)
#[derive(Clone, Serialize, Deserialize)]
pub struct RootKeyshareData {
    pub epoch: u64,
    pub ecdsa: <EcdsaSignatureProvider as SignatureProvider>::KeygenOutput,
}

/// A helper structure that allows loading each share separately.
/// It's useful when we want to introduce a new signature provider without breaking back-compatibility.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartialRootKeyshareData {
    pub epoch: u64,
    pub ecdsa: Option<<EcdsaSignatureProvider as SignatureProvider>::KeygenOutput>,
}

impl PartialRootKeyshareData {
    /// Returns a complete RootKeyshareData if all fields are set.
    pub(crate) fn as_complete(&self) -> Option<RootKeyshareData> {
        let Some(ecdsa) = self.ecdsa.clone() else {
            return None;
        };
        Some(RootKeyshareData { epoch: self.epoch, ecdsa })
    }
}

impl RootKeyshareData {
    pub fn new(epoch: u64, ecdsa: <EcdsaSignatureProvider as SignatureProvider>::KeygenOutput) -> Self {
        Self {
            epoch,
            ecdsa,
        }
    }

    /// If some data exists already, check that we can safely overwrite it
    fn compare_against_existing_share(
        to_save: &RootKeyshareData,
        existing: &PartialRootKeyshareData
    ) -> anyhow::Result<()> {
        match existing.as_complete() {
            // Key shares for all signature providers generated -> we do resharing
            //  -> we have to check, that epoch is greater than it was.
            Some(existing) => {
                if existing.epoch >= to_save.epoch {
                    return Err(anyhow::anyhow!(
                        "Refusing to overwrite existing keyshare of epoch {} with new keyshare of older epoch {}",
                        existing.epoch,
                        to_save.epoch,
                    ))
                }
            }

            // We are still generating a key share for some signature provider -> we have to make sure,
            //  that we do not overwrite existing key shares
            None => {
                if let Some(ecdsa) = &existing.ecdsa {
                    if ecdsa.private_share != to_save.ecdsa.private_share {
                        return Err(anyhow::anyhow!("Refusing to overwrite existing ecdsa keyshare"))
                    }
                }
            }
        };
        Ok(())
    }
}

/// Abstracts away the storage of the root keyshare data.
#[async_trait::async_trait]
pub trait KeyshareStorage: Send {
    /// Loads the most recent root keyshare data. Returns an error if the data
    /// cannot be read. Returns Ok(None) if the data does not exist (i.e. we've
    /// never participated successfully in a key generation).
    async fn load(&self) -> anyhow::Result<Option<PartialRootKeyshareData>>;

    /// Stores the most recent root keyshare data. This can only succeed if the
    /// keyshare didn't exist before or if the new data has a higher epoch.
    async fn store(&self, data: &RootKeyshareData) -> anyhow::Result<()>;
}

/// Factory to construct a KeyshareStorage implementation.
pub enum KeyshareStorageFactory {
    Gcp {
        project_id: String,
        secret_id: String,
    },
    Local {
        home_dir: std::path::PathBuf,
        encryption_key: [u8; 16],
    },
}

impl KeyshareStorageFactory {
    pub async fn create(&self) -> anyhow::Result<Box<dyn KeyshareStorage>> {
        match self {
            Self::Gcp {
                project_id,
                secret_id,
            } => {
                let storage =
                    gcp::GcpKeyshareStorage::new(project_id.clone(), secret_id.clone()).await?;
                Ok(Box::new(storage))
            }
            Self::Local {
                home_dir,
                encryption_key,
            } => {
                let storage = local::LocalKeyshareStorage::new(home_dir.clone(), *encryption_key);
                Ok(Box::new(storage))
            }
        }
    }
}
