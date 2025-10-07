pub mod compat;
mod gcp;
pub mod local;
pub mod permanent;
mod temporary;
#[cfg(test)]
pub mod test_utils;

use crate::trait_extensions::convert_to_contract_dto::IntoDtoType;
use anyhow::Context;
use mpc_contract::primitives::key_state::Keyset;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain};
use permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData};
use serde::{Deserialize, Serialize};
use temporary::{PendingKeyshareStorageHandle, TemporaryKeyStorage};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum KeyshareData {
    Secp256k1(threshold_signatures::ecdsa::KeygenOutput),
    Ed25519(threshold_signatures::eddsa::KeygenOutput),
    Bls12381(threshold_signatures::confidential_key_derivation::KeygenOutput),
}

/// A single keyshare, corresponding to one epoch, one domain, one attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keyshare {
    pub key_id: KeyEventId,
    pub data: KeyshareData,
}

impl Keyshare {
    pub fn public_key(&self) -> anyhow::Result<dtos_contract::PublicKey> {
        match &self.data {
            KeyshareData::Secp256k1(data) => Ok(data.public_key.into_dto_type()),
            KeyshareData::Ed25519(data) => Ok(data.public_key.into_dto_type()),
            KeyshareData::Bls12381(data) => Ok(data.public_key.into_dto_type()),
        }
    }

    pub fn check_consistency(&self, epoch_id: EpochId, key: &KeyForDomain) -> anyhow::Result<()> {
        let key_id = KeyEventId::new(epoch_id, key.domain_id, key.attempt);
        if self.key_id != key_id {
            anyhow::bail!(
                "Keyshare has incorrect key ID {:?}, should be {:?}",
                self.key_id,
                key_id
            );
        }
        let public_key: dtos_contract::PublicKey = key.key.clone().into();
        if self.public_key()? != public_key {
            anyhow::bail!(
                "Keyshare has incorrect public key {:?}, should be {:?}",
                self.public_key()?,
                key.key
            );
        }
        Ok(())
    }
}

/// Abstracts away the storage of the keyshares.
///
/// The keyshares are stored in "permanent key storage" and "temporary key storage":
///  - Permanent key storage is a single object that lives either on GCP or locally.
///  - Temporary key storage is a collection of keyshares that are persisted as individual files.
///    Each keyshare is identified by (epoch ID, domain ID, attempt ID).
///
/// Important: although "temporary key storage" uses the word "temporary", files must still be
/// strongly persisted and it is not acceptable to delete the local files. The persistence
/// requirements of the temporary and permanent key storages are the same (i.e. node operators
/// must not lose them, for doing so is the same as permanently leaving the MPC network).
///
/// Keyshares persisted into temporary key storage are not guaranteed to be used; rather, the
/// voting mechanism (vote_pk and vote_reshared) on the contract ultimately decides which
/// keyshare to use for each domain (in case multiple attempts were made to generate or reshare
/// the key).
///
/// Whenever the contract transitions into the Running state (which certifies the exact key to
/// use for each domain), the keyshares are promoted from temporary key storage to permanent key
/// storage. This is done by calling `load_keyset` when handling the Running state.
///
/// A subtle detail is that we may miss the Running state if it quickly transitions into
/// another state (Initializing or Resharing). For the initializing state we do not actually need
/// the existing keyshares, but for the resharing state we do. And that's not a problem:
/// in the resharing state we also need to call `load_keyset`, and that will promote the keys into
/// permanent storage if needed.
pub struct KeyshareStorage {
    temporary: TemporaryKeyStorage,
    permanent: PermanentKeyStorage,
}

impl KeyshareStorage {
    /// Before generating a key, we must call `ensure_can_generate_key` to check that we are able
    /// to generate that key and use it afterwards. This requires:
    ///  - The already generated keys exist either in permanent or temporary storage.
    ///  - The current permanent key storage is either
    ///    - In the same epoch as the key generation attempt, and whose keys are a prefix of the
    ///      already generated keys.
    ///    - In an older epoch. This can happen if we missed the previous transition from Resharing
    ///      to Running before it transitions again into Initializing. This is fine.
    ///  - We did not previously start generating the same key.
    ///
    /// Returns a handle to the keyshare storage, which must be used to commit the keyshare before
    /// the corresponding vote_pk call is made on the contract.
    pub async fn start_generating_key(
        &self,
        already_generated_keys: &[KeyForDomain],
        key_id_to_generate: KeyEventId,
    ) -> anyhow::Result<PendingKeyshareStorageHandle> {
        let permanent = self.permanent.load().await?;
        let epoch_id = key_id_to_generate.epoch_id;
        let num_permanent_keys_same_epoch = if let Some(permanent) = permanent {
            if permanent.epoch_id == epoch_id {
                Self::verify_existing_keyshares_are_prefix_of_keyset(
                    &permanent.keyshares,
                    epoch_id,
                    already_generated_keys,
                )?;
                permanent.keyshares.len()
            } else if permanent.epoch_id.get() > epoch_id.get() {
                anyhow::bail!(
                    "Permanent key storage has epoch ID {} which is newer than {}",
                    permanent.epoch_id.get(),
                    epoch_id.get()
                );
            } else {
                0
            }
        } else {
            0
        };
        for domain in &already_generated_keys[num_permanent_keys_same_epoch..] {
            self.load_keyshare_from_temporary(epoch_id, domain).await?;
        }
        self.temporary
            .start_generating_keyshare(key_id_to_generate)
            .await
    }

    /// Before resharing a key, we must call this to ensure that we're able to reshare the key
    /// and use it afterwards. This requires:
    ///   - The already reshared keys exist in temporary storage.
    ///   - The current permanent key storage has an older epoch.
    ///   - We did not previously start resharing for the same key ID.
    ///
    /// Returns a handle to the keyshare storage, which must be used to commit the keyshare before
    /// the corresponding vote_reshared call is made on the contract.
    pub async fn start_resharing_key(
        &self,
        already_reshared_keys: &[KeyForDomain],
        key_id_to_generate: KeyEventId,
    ) -> anyhow::Result<PendingKeyshareStorageHandle> {
        let permanent = self.permanent.load().await?;
        let epoch_id = key_id_to_generate.epoch_id;
        if let Some(permanent) = permanent {
            if permanent.epoch_id.get() >= epoch_id.get() {
                anyhow::bail!(
                    "Permanent key storage has epoch ID {} which is not older than {}",
                    permanent.epoch_id.get(),
                    epoch_id.get()
                );
            }
        }
        for domain in already_reshared_keys {
            self.load_keyshare_from_temporary(epoch_id, domain).await?;
        }
        self.temporary
            .start_generating_keyshare(key_id_to_generate)
            .await
    }

    /// Loads
    async fn _load_prefix_from_permanent(&self, keyset: &Keyset) -> anyhow::Result<Vec<Keyshare>> {
        let permanent = self.permanent.load().await?;
        let existing_keyshares = if let Some(permanent) = permanent {
            if permanent.epoch_id == keyset.epoch_id {
                permanent.keyshares
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        Self::verify_existing_keyshares_are_prefix_of_keyset(
            &existing_keyshares,
            keyset.epoch_id,
            &keyset.domains,
        )?;
        Ok(existing_keyshares)
    }

    async fn _store_new_permanent_keyset_data_delete_temporary(
        &self,
        epoch_id: EpochId,
        keyshares: Vec<Keyshare>,
    ) -> anyhow::Result<()> {
        let new_permanent_keyshare = PermanentKeyshareData::new(epoch_id, keyshares)?;
        self.permanent.store(&new_permanent_keyshare).await?;
        self.temporary
            .delete_keyshares_prior_to_epoch_id(epoch_id)
            .await?;
        Ok(())
    }

    /// Ensures that the given keyset is in permanent key storage, and then returns them. The order
    /// the keys are given and returned are both in increasing order of DomainId.
    ///
    /// Since this is only expected to be called when we already know which attempt to use, this
    /// function also deletes keyshares in temporary storage that are below the keyset's epoch ID.
    /// (We could also delete attempts in the same epoch ID but this is not necessary from a
    /// security perspective, since the same epoch ID corresponds to the same set of participants
    /// and the threshold value.)
    pub async fn load_keyset(&self, keyset: &Keyset) -> anyhow::Result<Vec<Keyshare>> {
        let existing_keyshares = self._load_prefix_from_permanent(keyset).await?;
        if existing_keyshares.len() == keyset.domains.len() {
            return Ok(existing_keyshares);
        }

        let mut new_keyshares = existing_keyshares;
        for domain in keyset.domains.iter().skip(new_keyshares.len()) {
            let key_id = KeyEventId::new(keyset.epoch_id, domain.domain_id, domain.attempt);
            let keyshare = self
                .temporary
                .load_keyshare(key_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing temporary keyshare {:?}", key_id))?;
            new_keyshares.push(keyshare);
        }

        self._store_new_permanent_keyset_data_delete_temporary(
            keyset.epoch_id,
            new_keyshares.clone(),
        )
        .await?;

        Ok(new_keyshares)
    }

    /// Helper function to verify that the keyshares we have from permanent storage is a prefix
    /// of the expected keyset, i.e. there are no extra keyshares, and each keyshare matches the
    /// keyset entry at the same index.
    fn verify_existing_keyshares_are_prefix_of_keyset(
        existing_keyshares: &[Keyshare],
        epoch_id: EpochId,
        expected_keys: &[KeyForDomain],
    ) -> anyhow::Result<()> {
        if existing_keyshares.len() > expected_keys.len() {
            anyhow::bail!(
                "Existing permanent keyshare for epoch {:?} has more domains {} than expected {}",
                epoch_id,
                existing_keyshares.len(),
                expected_keys.len()
            );
        }
        for (i, existing_keyshare) in existing_keyshares.iter().enumerate() {
            let domain = &expected_keys[i];
            existing_keyshare
                .check_consistency(epoch_id, domain)
                .with_context(|| {
                    format!(
                        "Existing permanent keyshare epoch {:?} index {}",
                        epoch_id, i
                    )
                })?;
        }
        Ok(())
    }

    /// Loads a keyshare from temporary storage and verifies that it is consistent with the given
    /// key's key ID and public key.
    async fn load_keyshare_from_temporary(
        &self,
        epoch_id: EpochId,
        key: &KeyForDomain,
    ) -> anyhow::Result<Keyshare> {
        let key_id = KeyEventId::new(epoch_id, key.domain_id, key.attempt);
        let keyshare = self
            .temporary
            .load_keyshare(key_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Missing temporary keyshare {:?}", key_id))?;
        keyshare
            .check_consistency(epoch_id, key)
            .with_context(|| format!("Keyshare loaded from temporary storage for {:?}", key_id))?;
        Ok(keyshare)
    }

    /// Imports keyshares from the provided backup into permanent storages.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The backup does not match the contract keyset’s epoch or domains,
    /// - The permanent keyshare storage is not empty.
    ///
    /// # Returns
    /// * `Ok(())` if the backup was successfully imported and stored permanently.
    /// * `Err(anyhow::Error)` if any validation or storage step fails.
    #[allow(dead_code)] // todo: remove after integration with onboarding function
    pub async fn import_backup(
        &mut self,
        backup: Vec<Keyshare>,
        contract_keyset: &Keyset,
    ) -> anyhow::Result<()> {
        // Ensure that the backup is a perfect match for the contract keyset
        Self::verify_existing_keyshares_are_prefix_of_keyset(
            &backup,
            contract_keyset.epoch_id,
            &contract_keyset.domains,
        )?;
        if backup.len() != contract_keyset.domains.len() {
            anyhow::bail!("backup keyshares is not an exact match for the contract keyset")
        }

        // Ensure we import into an empty Keystore
        let permanent = self.permanent.load().await?;
        if permanent.is_some() {
            anyhow::bail!("permanent keyshare storage isn't empty");
        }

        self._store_new_permanent_keyset_data_delete_temporary(
            contract_keyset.epoch_id,
            backup.clone(),
        )
        .await?;

        Ok(())
    }
}

pub struct GcpPermanentKeyStorageConfig {
    pub project_id: String,
    pub secret_id: String,
}

/// Config for how to construct a KeyshareStorage.
pub struct KeyStorageConfig {
    pub home_dir: std::path::PathBuf,
    pub local_encryption_key: [u8; 16],
    pub gcp: Option<GcpPermanentKeyStorageConfig>,
}

impl KeyStorageConfig {
    pub async fn create(&self) -> anyhow::Result<KeyshareStorage> {
        let permanent_backend: Box<dyn PermanentKeyStorageBackend> = if let Some(gcp) = &self.gcp {
            let backend = gcp::GcpPermanentKeyStorageBackend::new(
                gcp.project_id.clone(),
                gcp.secret_id.clone(),
            )
            .await?;
            Box::new(backend)
        } else {
            let backend = local::LocalPermanentKeyStorageBackend::new(
                self.home_dir.clone(),
                self.local_encryption_key,
            )
            .await?;
            Box::new(backend)
        };
        let permanent = PermanentKeyStorage::new(permanent_backend).await?;
        let temporary = TemporaryKeyStorage::new(self.home_dir.clone(), self.local_encryption_key)?;
        Ok(KeyshareStorage {
            temporary,
            permanent,
        })
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::{
        domain::DomainId,
        key_state::{AttemptId, EpochId, KeyEventId},
    };
    use tempfile::TempDir;

    use super::{KeyStorageConfig, KeyshareStorage};
    use crate::keyshare::{
        test_utils::{generate_dummy_keyshare, generate_dummy_keyshares, KeysetBuilder},
        Keyshare,
    };

    async fn generate_key_storage() -> (KeyshareStorage, TempDir) {
        let tempdir = tempfile::tempdir().unwrap();
        let home_dir = tempdir.path().to_path_buf();
        let local_encryption_key = [3; 16];
        let storage = KeyStorageConfig {
            home_dir,
            local_encryption_key,
            gcp: None,
        }
        .create()
        .await
        .unwrap();
        (storage, tempdir)
    }

    #[tokio::test]
    async fn test_key_storage() {
        let (storage, _tempdir) = generate_key_storage().await;

        let mut keyset = KeysetBuilder::new(0);

        // Load an empty keyset; this should succeed.
        let loaded0 = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert!(&loaded0.is_empty());

        // Store some keyshares.
        let key_1_epoch_0_non_final = generate_dummy_keyshare(0, 1, 1);
        let (key_1_epoch_0, key_1_epoch_0_alternate) = generate_dummy_keyshares(0, 1, 2);
        let (key_2_epoch_0, key_2_epoch_0_alternate) = generate_dummy_keyshares(0, 2, 1);
        let key_2_epoch_0_final = generate_dummy_keyshare(0, 2, 2);

        {
            // Before starting the good path, let's test that start_generating_key fails if called
            // when already-generated keys don't exist.
            let bad_keyset = KeysetBuilder::from_keyshares(0, &[key_1_epoch_0_non_final.clone()]);
            assert!(storage
                .start_generating_key(&bad_keyset.generated(), key_1_epoch_0_non_final.key_id)
                .await
                .is_err());
        }

        storage
            .start_generating_key(&keyset.generated(), key_1_epoch_0_non_final.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1_epoch_0_non_final.clone())
            .await
            .unwrap();
        storage
            .start_generating_key(&keyset.generated(), key_1_epoch_0.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1_epoch_0.clone())
            .await
            .unwrap();
        keyset.add_keyshare(key_1_epoch_0.clone());
        storage
            .start_generating_key(&keyset.generated(), key_2_epoch_0.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_2_epoch_0.clone())
            .await
            .unwrap();
        keyset.add_keyshare(key_2_epoch_0.clone());
        storage
            .start_generating_key(&keyset.generated(), key_2_epoch_0_final.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_2_epoch_0_final.clone())
            .await
            .unwrap();

        {
            // Check that we cannot start generating the same key again.
            assert!(storage
                .start_generating_key(&keyset.generated(), key_2_epoch_0_final.key_id)
                .await
                .is_err());
        }

        // Finalize two keys from epoch 0.
        let loaded1 = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded1, &keyset.keyshares());

        // Load a conflicting keyset; this should fail.
        let conflicting_keyset = KeysetBuilder::from_keyshares(
            0,
            &[key_1_epoch_0_non_final.clone(), key_2_epoch_0_final.clone()],
        );
        assert!(storage
            .load_keyset(&conflicting_keyset.keyset())
            .await
            .is_err());

        // Load the same keyset again; this should succeed.
        let loaded1 = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded1, &keyset.keyshares());

        // Store some more keyshares as part of resharing, for epoch 1.
        let key_1_epoch_1 = Keyshare {
            key_id: KeyEventId::new(EpochId::new(1), DomainId(1), AttemptId::new().next()),
            data: key_1_epoch_0_alternate.data.clone(),
        };
        let key_1_epoch_1_invalid = generate_dummy_keyshare(1, 1, 2);
        let key_2_epoch_1_invalid = generate_dummy_keyshare(1, 2, 1);
        let key_2_epoch_1 = Keyshare {
            key_id: KeyEventId::new(EpochId::new(1), DomainId(2), AttemptId::new().next().next()),
            data: key_2_epoch_0_alternate.data.clone(),
        };

        let old_keyset = keyset;

        {
            // Before starting the good path, let's test that start_resharing fails if called
            // when already-reshared keys don't exist.
            let bad_keyset = KeysetBuilder::from_keyshares(1, &[key_1_epoch_1.clone()]);
            assert!(storage
                .start_resharing_key(&bad_keyset.generated(), key_1_epoch_1.key_id)
                .await
                .is_err());
        }

        let mut keyset = KeysetBuilder::from_keyshares(1, &[]);
        storage
            .start_resharing_key(&keyset.generated(), key_1_epoch_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1_epoch_1.clone())
            .await
            .unwrap();
        keyset.add_keyshare(key_1_epoch_1.clone());
        storage
            .start_resharing_key(&keyset.generated(), key_1_epoch_1_invalid.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1_epoch_1_invalid.clone())
            .await
            .unwrap();
        storage
            .start_resharing_key(&keyset.generated(), key_2_epoch_1_invalid.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_2_epoch_1_invalid.clone())
            .await
            .unwrap();
        storage
            .start_resharing_key(&keyset.generated(), key_2_epoch_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_2_epoch_1.clone())
            .await
            .unwrap();

        {
            // Check that we cannot start resharing the same key again.
            assert!(storage
                .start_resharing_key(&keyset.generated(), key_2_epoch_1.key_id)
                .await
                .is_err());
        }

        {
            // Check that finalizing an invalid key is not possible
            let mut invalid_keyset = keyset.clone();
            invalid_keyset.add_keyshare(key_2_epoch_1_invalid);
            assert!(storage.load_keyset(&keyset.keyset()).await.is_err());
        }
        keyset.add_keyshare(key_2_epoch_1.clone());

        // Finalize two keys from epoch 1.
        let loaded3 = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded3, &keyset.keyshares());

        // Cannot load the old keyset anymore.
        assert!(storage.load_keyset(&old_keyset.keyset()).await.is_err());

        // Add another key to the same epoch via key generation; this is fine.
        let key_3_epoch_1 = generate_dummy_keyshare(1, 3, 1);
        storage
            .start_generating_key(&keyset.generated(), key_3_epoch_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_3_epoch_1.clone())
            .await
            .unwrap();
        keyset.add_keyshare(key_3_epoch_1.clone());
        let loaded4 = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded4, &keyset.keyshares());
    }

    async fn populate_permanent_keystore(
        keyshare: Keyshare,
        keyset: &mut KeysetBuilder,
        storage: &KeyshareStorage,
    ) {
        storage
            .start_generating_key(&keyset.generated(), keyshare.key_id)
            .await
            .unwrap()
            .commit_keyshare(keyshare.clone())
            .await
            .unwrap();
        keyset.add_keyshare(keyshare.clone());
        let loaded = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded, &keyset.keyshares());
    }

    /// Import keyshares into an empty KeyshareStorage.
    #[tokio::test]
    async fn test_import_backup_success_empty() {
        let epoch_id = 1;
        let key_1 = generate_dummy_keyshare(epoch_id, 1, 0);
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3);
        let keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1, key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        assert!(storage
            .import_backup(keyset.keyshares().to_vec(), &keyset.keyset())
            .await
            .is_ok());

        let loaded = storage.load_keyset(&keyset.keyset()).await.unwrap();
        assert_eq!(&loaded, &keyset.keyshares());
    }

    /// Fail to import keyshares into a populated KeyshareStorage.
    #[tokio::test]
    async fn test_import_backup_failure_populated() {
        let epoch_id = 1;

        let (mut storage, _tempdir) = generate_key_storage().await;
        let existing_key = generate_dummy_keyshare(epoch_id, 2, 3);
        let mut existing_keyset = KeysetBuilder::from_keyshares(epoch_id, &[]);
        populate_permanent_keystore(existing_key, &mut existing_keyset, &storage).await;

        let key_1 = generate_dummy_keyshare(epoch_id, 1, 0);
        let keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1]);

        assert!(storage
            .import_backup(keyset.keyshares().to_vec(), &keyset.keyset())
            .await
            .is_err());

        let loaded = storage
            .load_keyset(&existing_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &existing_keyset.keyshares());
    }
}
