pub mod gcp;
pub mod local;

use cait_sith::KeygenOutput;
use k256::{AffinePoint, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};

/// The root keyshare data along with an epoch. The epoch is incremented
/// for each key resharing. This is the format stored in the old MPC
/// implementation, and we're keeping it the same to ease migration.
#[derive(Clone, Serialize, Deserialize)]
pub struct RootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

impl RootKeyshareData {
    pub fn keygen_output(&self) -> KeygenOutput<Secp256k1> {
        KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        }
    }

    pub fn new(epoch: u64, keygen_output: KeygenOutput<Secp256k1>) -> Self {
        Self {
            epoch,
            private_share: keygen_output.private_share,
            public_key: keygen_output.public_key,
        }
    }
}

/// Abstracts away the storage of the root keyshare data.
#[async_trait::async_trait]
pub trait KeyshareStorage: Send {
    /// Loads the most recent root keyshare data. Returns an error if the data
    /// cannot be read. Returns Ok(None) if the data does not exist (i.e. we've
    /// never participated successfully in a key generation).
    async fn load(&self) -> anyhow::Result<Option<RootKeyshareData>>;

    /// Stores the most recent root keyshare data. This can only succeed if the
    /// keyshare didn't exist before or if the new data has a higher epoch.
    async fn store(&self, data: &RootKeyshareData) -> anyhow::Result<()>;
}
