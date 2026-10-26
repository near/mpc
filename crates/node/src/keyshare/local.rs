use super::permanent::PermanentKeyStorageBackend;
use crate::db;
use crate::durable_fs::{rename_durably, sync_parent_dir};
use crate::home_paths::{permanent_key_link, permanent_keys_dir};
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Stores the permanent keyshare in a local encrypted file.
pub struct LocalPermanentKeyStorageBackend {
    home_dir: PathBuf,
    permanent_key_dir: PathBuf,
    encryption_key: [u8; 16],
}

impl LocalPermanentKeyStorageBackend {
    pub async fn new(home_dir: PathBuf, key: [u8; 16]) -> anyhow::Result<Self> {
        let permanent_key_dir = permanent_keys_dir(&home_dir);
        tokio::fs::create_dir_all(&permanent_key_dir).await?;
        Ok(Self {
            home_dir,
            permanent_key_dir,
            encryption_key: key,
        })
    }
}

#[async_trait::async_trait]
impl PermanentKeyStorageBackend for LocalPermanentKeyStorageBackend {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let keyfile = permanent_key_link(&self.home_dir);
        if !keyfile.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(&keyfile)
            .await
            .context("Failed to read key file")?;
        let cipher = Aes128Gcm::new(&self.encryption_key.into());
        let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt key file")?;
        Ok(Some(decrypted))
    }

    async fn store(&self, data: &[u8], identifier: &str) -> anyhow::Result<()> {
        let cipher = Aes128Gcm::new(&self.encryption_key.into());
        let encrypted = db::encrypt(&cipher, data);
        // Write the new permanent keyshare to a separate file, and then create a link to it.
        // That way, we don't lose any keys if we somehow mess up.
        let keyfile_for_epoch = self.permanent_key_dir.join(identifier);
        let mut file = tokio::fs::File::create_new(&keyfile_for_epoch)
            .await
            .context("Failed to create PermanentKeyshareData file")?;
        file.write_all(&encrypted)
            .await
            .context("Failed to write PermanentKeyshareData file")?;
        file.sync_all()
            .await
            .context("Failed to sync PermanentKeyshareData file")?;
        drop(file);

        // Replace `key` with a rename, never deleting it first: `load` treats a missing `key`
        // as no keyshare.
        let keyfile = permanent_key_link(&self.home_dir);
        let keyfile_tmp = keyfile.with_added_extension("tmp");
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            sync_parent_dir(&keyfile_for_epoch)
                .context("Failed to sync the permanent keys directory")?;
            std::fs::remove_file(&keyfile_tmp).ok(); // left behind by an interrupted store
            std::fs::hard_link(&keyfile_for_epoch, &keyfile_tmp)
                .context("Failed to link PermanentKeyshareData file")?;
            rename_durably(&keyfile_tmp, &keyfile).context("Failed to replace the key link")?;
            Ok(())
        })
        .await
        .context("key link task failed")??;
        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::keyshare::local::LocalPermanentKeyStorageBackend;
    use crate::keyshare::permanent::PermanentKeyStorageBackend;

    #[tokio::test]
    async fn test_local_keyshare_storage_backend() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let storage =
            LocalPermanentKeyStorageBackend::new(dir.path().to_path_buf(), encryption_key)
                .await
                .unwrap();
        assert!(storage.load().await.unwrap().is_none());
        storage.store(b"123", "id1").await.unwrap();
        assert_eq!(storage.load().await.unwrap().unwrap(), b"123");
        storage.store(b"456", "id2").await.unwrap();
        assert_eq!(storage.load().await.unwrap().unwrap(), b"456");
        assert!(std::fs::exists(dir.path().join("permanent_keys/id1")).unwrap());
    }

    #[tokio::test]
    async fn store__should_replace_key_link_even_with_stale_temp_link() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalPermanentKeyStorageBackend::new(dir.path().to_path_buf(), [1; 16])
            .await
            .unwrap();
        storage.store(b"123", "id1").await.unwrap();
        std::fs::write(dir.path().join("key.tmp"), b"stale").unwrap();

        // When
        storage.store(b"456", "id2").await.unwrap();

        // Then
        assert_eq!(storage.load().await.unwrap().unwrap(), b"456");
        assert!(!std::fs::exists(dir.path().join("key.tmp")).unwrap());
    }
}
