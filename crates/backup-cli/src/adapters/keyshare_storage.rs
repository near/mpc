use mpc_node::keyshare::{
    Keyshare, local::LocalPermanentKeyStorageBackend, permanent::PermanentKeyStorage,
    permanent::PermanentKeyshareData,
};
use std::path::PathBuf;

use crate::ports::KeyShareRepository;

/// Adapter that provides simple keyshare persistence for the backup service.
///
/// This uses the MPC node's [`PermanentKeyStorage`] to store keyshares locally
/// in an encrypted format.
pub struct KeyshareStorageAdapter {
    storage: PermanentKeyStorage,
}

impl KeyshareStorageAdapter {
    pub async fn new(home_dir: PathBuf, encryption_key: [u8; 16]) -> anyhow::Result<Self> {
        let backend = LocalPermanentKeyStorageBackend::new(home_dir, encryption_key).await?;
        let storage = PermanentKeyStorage::new(Box::new(backend)).await?;

        Ok(Self { storage })
    }
}

impl KeyShareRepository for KeyshareStorageAdapter {
    type Error = anyhow::Error;

    async fn store_keyshares(&self, key_shares: &[Keyshare]) -> Result<(), Self::Error> {
        let Some(first) = key_shares.first() else {
            anyhow::bail!("Cannot store empty keyshares");
        };
        let epoch_id = first.key_id.epoch_id;

        // PermanentKeyshareData::new validates consistency of keyshares
        let permanent_data = PermanentKeyshareData::new(epoch_id, key_shares.to_vec())?;
        self.storage.store(&permanent_data).await?;

        Ok(())
    }

    async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
        let data = self.storage.load().await?;

        match data {
            Some(permanent_data) => Ok(permanent_data.keyshares),
            None => Ok(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_node::keyshare::test_utils::generate_dummy_keyshare;
    use rand::SeedableRng;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_store_and_load_keyshares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let temp_dir = tempdir().unwrap();
        let encryption_key = [42u8; 16];
        let storage = KeyshareStorageAdapter::new(temp_dir.path().to_path_buf(), encryption_key)
            .await
            .unwrap();
        let keyshares = vec![
            generate_dummy_keyshare(1, 0, 1, &mut rng),
            generate_dummy_keyshare(1, 1, 1, &mut rng),
        ];

        // When
        storage.store_keyshares(&keyshares).await.unwrap();

        // Then
        let loaded = storage.load_keyshares().await.unwrap();
        assert_eq!(loaded, keyshares);
    }

    #[tokio::test]
    async fn test_store_empty_keyshares_fails() {
        // Given
        let temp_dir = tempdir().unwrap();
        let encryption_key = [42u8; 16];
        let storage = KeyshareStorageAdapter::new(temp_dir.path().to_path_buf(), encryption_key)
            .await
            .unwrap();

        // When
        let result = storage.store_keyshares(&[]).await;

        // Then
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot store empty keyshares")
        );
    }

    #[tokio::test]
    async fn test_store_inconsistent_epochs_fails() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let temp_dir = tempdir().unwrap();
        let encryption_key = [42u8; 16];
        let storage = KeyshareStorageAdapter::new(temp_dir.path().to_path_buf(), encryption_key)
            .await
            .unwrap();
        let keyshares = vec![
            generate_dummy_keyshare(1, 0, 1, &mut rng),
            generate_dummy_keyshare(2, 1, 1, &mut rng), // Different epoch!
        ];

        // When
        let result = storage.store_keyshares(&keyshares).await;

        // Then
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Inconsistent"));
    }

    #[tokio::test]
    async fn test_load_before_store_returns_empty() {
        // Given
        let temp_dir = tempdir().unwrap();
        let encryption_key = [42u8; 16];
        let storage = KeyshareStorageAdapter::new(temp_dir.path().to_path_buf(), encryption_key)
            .await
            .unwrap();

        // When
        let loaded = storage.load_keyshares().await.unwrap();

        // Then
        assert_eq!(loaded.len(), 0);
    }

    #[tokio::test]
    async fn test_cannot_downgrade_epoch() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let temp_dir = tempdir().unwrap();
        let encryption_key = [42u8; 16];
        let storage = KeyshareStorageAdapter::new(temp_dir.path().to_path_buf(), encryption_key)
            .await
            .unwrap();
        let keyshares1 = vec![generate_dummy_keyshare(2, 0, 1, &mut rng)];
        storage.store_keyshares(&keyshares1).await.unwrap();

        // When
        let keyshares2 = vec![generate_dummy_keyshare(1, 0, 1, &mut rng)];
        let result = storage.store_keyshares(&keyshares2).await;

        // Then
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("older epoch"));
    }
}
