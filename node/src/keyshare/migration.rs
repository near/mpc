//! This is a temporal code which addresses migration from old format,
//!  when we didn't have distinction on `SignatureProviders`.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use crate::keyshare::{KeyshareStorage, PartialRootKeyshareData};
use k256::{AffinePoint, Scalar};
use serde::{Deserialize, Serialize};
use crate::db;
use crate::keyshare::local::LocalKeyshareStorage;
use crate::tests::TestGenerators;

#[derive(Clone, Serialize, Deserialize)]
pub struct OldRootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

pub(crate) fn try_load_from_old_keyshare(data: &[u8]) -> Option<PartialRootKeyshareData> {
    serde_json::from_slice::<OldRootKeyshareData>(&data)
        .ok()
        .map(|data| PartialRootKeyshareData {
            epoch: data.epoch,
            ecdsa: Some(cait_sith::KeygenOutput {
                private_share: data.private_share,
                public_key: data.public_key,
            }),
        })
}

#[tokio::test]
async fn test_local_keyshare_storage() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let key_path = dir_path.join("key");

    let encryption_key = [1; 16];

    let old_keyshare = {
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        OldRootKeyshareData {
            epoch: 42,
            private_share: generated_key.private_share,
            public_key: generated_key.public_key,
        }
    };

    // Save data into old keyshare format
    {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        let data = serde_json::to_vec(&old_keyshare).context("Failed to serialize keygen")?;
        let encrypted = db::encrypt(&cipher, &data);
        tokio::fs::write(&key_path, &encrypted)
            .await?;
    }

    let storage = LocalKeyshareStorage::new(dir_path, encryption_key);
    let loaded_key = storage.load().await?.unwrap();
    let ecdsa = loaded_key.ecdsa.as_ref().unwrap();
    assert_eq!(old_keyshare.private_share, ecdsa.private_share);
    assert_eq!(old_keyshare.public_key, ecdsa.public_key);
    assert_eq!(old_keyshare.epoch, loaded_key.epoch);
    Ok(())
}
