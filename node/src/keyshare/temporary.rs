use super::KeyShare;
use crate::db::{decrypt, encrypt};
use aes_gcm::{Aes128Gcm, KeyInit};
use mpc_contract::primitives::key_state::{EpochId, KeyEventId};
use sha3::digest::generic_array::GenericArray;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub struct TemporaryKeyStorage {
    storage_dir: PathBuf,
    cipher: Aes128Gcm,
}

impl TemporaryKeyStorage {
    pub fn new(home_dir: PathBuf, local_encryption_key: [u8; 16]) -> anyhow::Result<Self> {
        let storage_dir = home_dir.join("temporary_keys");
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self {
            storage_dir,
            cipher: Aes128Gcm::new(GenericArray::from_slice(&local_encryption_key)),
        })
    }

    fn keyshare_path(&self, key_id: &KeyEventId) -> PathBuf {
        let filename = format!(
            "keyshare_{}_{}_{}",
            key_id.epoch_id.get(),
            key_id.domain_id.0,
            key_id.attempt_id.get()
        );
        self.storage_dir.join(filename)
    }

    pub async fn store_keyshare(&self, keyshare: KeyShare) -> anyhow::Result<()> {
        let path = self.keyshare_path(&keyshare.key_id);
        let data = serde_json::to_vec(&keyshare)?;
        let encrypted = encrypt(&self.cipher, &data);

        let mut file = tokio::fs::File::create_new(&path).await?;
        file.write_all(&encrypted).await?;
        file.sync_all().await?;
        Ok(())
    }

    pub async fn load_keyshare(&self, key_id: &KeyEventId) -> anyhow::Result<Option<KeyShare>> {
        let path = self.keyshare_path(key_id);
        if tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let decrypted = decrypt(&self.cipher, &data)?;
        let keyshare: KeyShare = serde_json::from_slice(&decrypted)?;
        if keyshare.key_id != *key_id {
            anyhow::bail!(
                "Keyshare loaded from {:?} has unexpected key ID {:?}",
                path,
                keyshare.key_id
            );
        }
        Ok(Some(keyshare))
    }

    fn get_epoch_id_from_filename(filename: &str) -> anyhow::Result<EpochId> {
        let parts: Vec<&str> = filename.split('_').collect();
        if parts.len() != 4 {
            anyhow::bail!("Invalid keyshare filename: {:?}", filename);
        }
        let epoch_id: u64 = parts[1].parse()?;
        Ok(EpochId::new(epoch_id))
    }

    pub async fn delete_keyshares_prior_to_epoch_id(
        &self,
        epoch_id: EpochId,
    ) -> anyhow::Result<()> {
        let mut readdir = tokio::fs::read_dir(&self.storage_dir).await?;
        while let Some(entry) = readdir.next_entry().await? {
            let filename = entry.file_name().to_string_lossy().to_string();
            let existing_epoch_id = Self::get_epoch_id_from_filename(&filename)?;
            if existing_epoch_id.get() < epoch_id.get() {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::keyshare::temporary::TemporaryKeyStorage;
    use crate::keyshare::test_utils::generate_dummy_keyshare;
    use mpc_contract::primitives::key_state::EpochId;

    #[tokio::test]
    async fn test_temporary_key_storage() {
        let home_dir = tempfile::tempdir().unwrap();
        let local_encryption_key = [3; 16];
        let storage =
            TemporaryKeyStorage::new(home_dir.path().to_path_buf(), local_encryption_key).unwrap();

        let key1 = generate_dummy_keyshare(1, 2, 1);
        let key2 = generate_dummy_keyshare(1, 2, 2);
        let key3 = generate_dummy_keyshare(1, 2, 3);
        let key4 = generate_dummy_keyshare(1, 3, 2);
        let key5 = generate_dummy_keyshare(2, 1, 1);
        let key6 = generate_dummy_keyshare(2, 2, 1);
        let key7 = generate_dummy_keyshare(3, 1, 7);

        assert!(storage.load_keyshare(&key1.key_id).await.unwrap().is_none());

        storage.store_keyshare(key1.clone()).await.unwrap();
        storage.store_keyshare(key2.clone()).await.unwrap();
        storage.store_keyshare(key3.clone()).await.unwrap();
        storage.store_keyshare(key4.clone()).await.unwrap();
        storage.store_keyshare(key5.clone()).await.unwrap();
        storage.store_keyshare(key6.clone()).await.unwrap();
        storage.store_keyshare(key7.clone()).await.unwrap();

        let loaded1 = storage.load_keyshare(&key1.key_id).await.unwrap().unwrap();
        assert_eq!(loaded1, key1);
        let loaded2 = storage.load_keyshare(&key2.key_id).await.unwrap().unwrap();
        assert_eq!(loaded2, key2);
        let loaded3 = storage.load_keyshare(&key3.key_id).await.unwrap().unwrap();
        assert_eq!(loaded3, key3);
        let loaded4 = storage.load_keyshare(&key4.key_id).await.unwrap().unwrap();
        assert_eq!(loaded4, key4);
        let loaded5 = storage.load_keyshare(&key5.key_id).await.unwrap().unwrap();
        assert_eq!(loaded5, key5);
        let loaded6 = storage.load_keyshare(&key6.key_id).await.unwrap().unwrap();
        assert_eq!(loaded6, key6);
        let loaded7 = storage.load_keyshare(&key7.key_id).await.unwrap().unwrap();
        assert_eq!(loaded7, key7);

        storage
            .delete_keyshares_prior_to_epoch_id(EpochId::new(2))
            .await
            .unwrap();
        assert!(storage.load_keyshare(&key1.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key2.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key3.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key4.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key5.key_id).await.unwrap().is_some());
        assert!(storage.load_keyshare(&key6.key_id).await.unwrap().is_some());
        assert!(storage.load_keyshare(&key7.key_id).await.unwrap().is_some());

        storage
            .delete_keyshares_prior_to_epoch_id(EpochId::new(3))
            .await
            .unwrap();

        assert!(storage.load_keyshare(&key5.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key6.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(&key7.key_id).await.unwrap().is_some());
    }
}
