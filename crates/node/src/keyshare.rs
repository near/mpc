pub mod compat;
mod gcp;
pub mod local;
pub mod permanent;
mod temporary;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use anyhow::Context;
use mpc_contract::primitives::key_state::Keyset;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain};
use permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData};
use serde::{Deserialize, Serialize};
use temporary::{PendingKeyshareStorageHandle, TemporaryKeyStorage};

use contract_interface::types as dtos;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum KeyshareData {
    Secp256k1(threshold_signatures::ecdsa::KeygenOutput),
    Ed25519(threshold_signatures::frost::eddsa::KeygenOutput),
    Bls12381(threshold_signatures::confidential_key_derivation::KeygenOutput),
    V2Secp256k1(threshold_signatures::ecdsa::KeygenOutput),
}

/// A single keyshare, corresponding to one epoch, one domain, one attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keyshare {
    pub key_id: KeyEventId,
    pub data: KeyshareData,
}

impl Keyshare {
    pub fn public_key(&self) -> anyhow::Result<contract_interface::types::PublicKey> {
        match &self.data {
            KeyshareData::Secp256k1(data) => Ok(data.public_key.into_contract_interface_type()),
            KeyshareData::Ed25519(data) => Ok(data.public_key.into_contract_interface_type()),
            KeyshareData::Bls12381(data) => Ok(data.public_key.into_contract_interface_type()),
            KeyshareData::V2Secp256k1(data) => Ok(data.public_key.into_contract_interface_type()),
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
        let public_key: dtos::PublicKey = key.key.clone().into();
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

enum LoadedKeyset {
    Permanent(Vec<Keyshare>),
    PermanentAndTemporary(Vec<Keyshare>),
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
        &mut self,
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
        &mut self,
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
        &mut self,
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

    async fn _load_keyshares_from_permanent_or_temporary(
        &self,
        keyset: &Keyset,
    ) -> anyhow::Result<LoadedKeyset> {
        let existing_keyshares = self._load_prefix_from_permanent(keyset).await?;
        if existing_keyshares.len() == keyset.domains.len() {
            return Ok(LoadedKeyset::Permanent(existing_keyshares));
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
        Ok(LoadedKeyset::PermanentAndTemporary(new_keyshares))
    }

    /// Ensures that the given keyset is in permanent key storage, and then returns them. The order
    /// the keys are given and returned are both in increasing order of DomainId.
    ///
    /// Since this is only expected to be called when we already know which attempt to use, this
    /// function also deletes keyshares in temporary storage that are below the keyset's epoch ID.
    /// (We could also delete attempts in the same epoch ID but this is not necessary from a
    /// security perspective, since the same epoch ID corresponds to the same set of participants
    /// and the threshold value.)
    pub async fn update_permanent_keyshares(
        &mut self,
        keyset: &Keyset,
    ) -> anyhow::Result<Vec<Keyshare>> {
        match self
            ._load_keyshares_from_permanent_or_temporary(keyset)
            .await?
        {
            LoadedKeyset::Permanent(keyshares) => Ok(keyshares),
            LoadedKeyset::PermanentAndTemporary(keyshares) => {
                self._store_new_permanent_keyset_data_delete_temporary(
                    keyset.epoch_id,
                    keyshares.clone(),
                )
                .await?;
                Ok(keyshares)
            }
        }
    }

    /// Given a keyset, get the corresponding Keyshares
    pub async fn get_keyshares(&self, keyset: &Keyset) -> anyhow::Result<Vec<Keyshare>> {
        match self
            ._load_keyshares_from_permanent_or_temporary(keyset)
            .await?
        {
            LoadedKeyset::Permanent(keyshares) => Ok(keyshares),
            LoadedKeyset::PermanentAndTemporary(keyshares) => Ok(keyshares),
        }
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
    /// The following validation is performed:
    /// - the provided backup shares [`Keyshare`] must be an exact match for the provided conrtact_keyset [`Keyset`]
    /// - if the **permanent** KeyshareStorage contains keyshares of the same epoch, then they must be a prefix of the provided backup shares.
    /// - if the **temporary** KeyshareStorage contains any keyshares of matching [`KeyEventId`],
    ///   then they must be an exact match for the keyshares provided in the backup.
    ///
    /// Any keyshares present missing in the temporary or local Keyshare storage are drawn from the
    /// provided backup.
    ///
    /// If the validation passes, then the constructed keyset is stored to permanent
    /// KeyshareStorage and any temporary keyshares of younger epoch ids are permanently deleted.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The backup does not match the contract keyset’s epoch or domains,
    /// - A required keyshare is missing in both temporary storage and backup,
    /// - The reconstructed keyshares differ from the backup (indicating corruption),
    /// - Or storing to permanent storage fails.
    ///
    /// # Returns
    /// * `Ok(())` if the backup was successfully imported and stored permanently.
    /// * `Err(anyhow::Error)` if any validation or storage step fails.
    pub async fn import_backup(
        // while technically not required to be mut, we must not call write functions in parallel
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

        // We load all keys we have stored in permanent or temporary storage and only draw from
        // backup in case we are missing shares.
        let existing_keyshares = self._load_prefix_from_permanent(contract_keyset).await?;
        let mut new_keyshares = existing_keyshares;
        for domain in contract_keyset.domains.iter().skip(new_keyshares.len()) {
            let key_id =
                KeyEventId::new(contract_keyset.epoch_id, domain.domain_id, domain.attempt);

            // if we don't have the keyshare in temporary storage, we load it from the backup
            let keyshare: Keyshare = self
                .temporary
                .load_keyshare(key_id)
                .await?
                .or_else(|| backup.iter().find(|share| share.key_id == key_id).cloned())
                .ok_or_else(|| anyhow::anyhow!("missing keyshare {:?}", key_id))?;
            new_keyshares.push(keyshare);
        }

        // finally, we check that the constructed keyset matches the backup
        let consistent_keyset = new_keyshares
            .iter()
            .zip(&backup)
            .all(|(constructed_share, backup_share)| constructed_share == backup_share);
        if !consistent_keyset {
            let inconsistent_shares: Vec<KeyEventId> = new_keyshares
                .iter()
                .zip(&backup)
                .filter_map(|(constructed_share, backup_share)| {
                    if constructed_share != backup_share {
                        Some(constructed_share.key_id)
                    } else {
                        None
                    }
                })
                .collect();
            anyhow::bail!("corrupted backup or corrupted keystore: found a mismatch between secret shares for key_ids: {:?}.", inconsistent_shares);
        }

        self._store_new_permanent_keyset_data_delete_temporary(
            contract_keyset.epoch_id,
            new_keyshares.clone(),
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

#[cfg(any(test, feature = "test-utils"))]
pub fn generate_key_storage_config() -> (KeyStorageConfig, tempfile::TempDir) {
    let tempdir = tempfile::tempdir().unwrap();
    let home_dir = tempdir.path().to_path_buf();
    let local_encryption_key = [3; 16];
    (
        KeyStorageConfig {
            home_dir,
            local_encryption_key,
            gcp: None,
        },
        tempdir,
    )
}

// When using this function, tempdir must not be dropped, else the folder is erased
#[cfg(any(test, feature = "test-utils"))]
pub async fn generate_key_storage() -> (KeyshareStorage, tempfile::TempDir) {
    let (storage_config, tempdir) = generate_key_storage_config();
    (storage_config.create().await.unwrap(), tempdir)
}

#[cfg(test)]
pub mod tests {
    use mpc_contract::primitives::{
        domain::DomainId,
        key_state::{AttemptId, EpochId, KeyEventId},
    };
    use rand::SeedableRng as _;

    use super::{generate_key_storage, KeyshareStorage};
    use crate::keyshare::{
        test_utils::{generate_dummy_keyshare, generate_dummy_keyshares, KeysetBuilder},
        Keyshare,
    };

    #[tokio::test]
    async fn test_key_storage() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let (mut storage, _tempdir) = generate_key_storage().await;

        let mut keyset = KeysetBuilder::new(0);

        // Load an empty keyset; this should succeed.
        let loaded0 = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert!(&loaded0.is_empty());

        // Store some keyshares.
        let key_1_epoch_0_non_final = generate_dummy_keyshare(0, 1, 1, &mut rng);
        let (key_1_epoch_0, key_1_epoch_0_alternate) = generate_dummy_keyshares(0, 1, 2, &mut rng);
        let (key_2_epoch_0, key_2_epoch_0_alternate) = generate_dummy_keyshares(0, 2, 1, &mut rng);
        let key_2_epoch_0_final = generate_dummy_keyshare(0, 2, 2, &mut rng);

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
        let loaded1 = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded1, &keyset.keyshares());

        // Load a conflicting keyset; this should fail.
        let conflicting_keyset = KeysetBuilder::from_keyshares(
            0,
            &[key_1_epoch_0_non_final.clone(), key_2_epoch_0_final.clone()],
        );
        let _ = storage
            .update_permanent_keyshares(&conflicting_keyset.keyset())
            .await
            .unwrap_err();

        // Load the same keyset again; this should succeed.
        let loaded1 = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded1, &keyset.keyshares());

        // Store some more keyshares as part of resharing, for epoch 1.
        let key_1_epoch_1 = Keyshare {
            key_id: KeyEventId::new(EpochId::new(1), DomainId(1), AttemptId::new().next()),
            data: key_1_epoch_0_alternate.data.clone(),
        };
        let key_1_epoch_1_invalid = generate_dummy_keyshare(1, 1, 2, &mut rng);
        let key_2_epoch_1_invalid = generate_dummy_keyshare(1, 2, 1, &mut rng);
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
            let _ = storage
                .update_permanent_keyshares(&keyset.keyset())
                .await
                .unwrap_err();
        }
        keyset.add_keyshare(key_2_epoch_1.clone());

        // Finalize two keys from epoch 1.
        let loaded3 = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded3, &keyset.keyshares());

        // Cannot load the old keyset anymore.
        let _ = storage
            .update_permanent_keyshares(&old_keyset.keyset())
            .await
            .unwrap_err();

        // Add another key to the same epoch via key generation; this is fine.
        let key_3_epoch_1 = generate_dummy_keyshare(1, 3, 1, &mut rng);
        storage
            .start_generating_key(&keyset.generated(), key_3_epoch_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_3_epoch_1.clone())
            .await
            .unwrap();
        keyset.add_keyshare(key_3_epoch_1.clone());
        let loaded4 = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded4, &keyset.keyshares());
    }

    pub async fn populate_permanent_keystore(
        keyshare: Keyshare,
        keyset: &mut KeysetBuilder,
        storage: &mut KeyshareStorage,
    ) {
        storage
            .start_generating_key(&keyset.generated(), keyshare.key_id)
            .await
            .unwrap()
            .commit_keyshare(keyshare.clone())
            .await
            .unwrap();
        keyset.add_keyshare(keyshare.clone());
        let loaded = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &keyset.keyshares());
    }

    /// Import keyshares into an empty KeyshareStorage.
    #[tokio::test]
    async fn test_import_backup_success_empty() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_1 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1, key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        storage
            .import_backup(keyset.keyshares().to_vec(), &keyset.keyset())
            .await
            .expect("Backup import should succeed for empty storage");

        let loaded = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &keyset.keyshares());
    }

    /// Import keyshares into KeyshareStorage with an existing, matching share in permanent storage.
    /// Ensure we import the missing share from backup.
    #[tokio::test]
    async fn test_import_backup_success_existing_shares_permanent() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_1 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let full_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1.clone(), key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        {
            // populate the permanent keystore with the first key, but not the second
            let mut partial_keyset = KeysetBuilder::from_keyshares(epoch_id, &[]);
            populate_permanent_keystore(key_1, &mut partial_keyset, &mut storage).await;
        }
        let res = storage
            .import_backup(full_keyset.keyshares().to_vec(), &full_keyset.keyset())
            .await;
        res.expect("Backup import should succeed with matching permanent shares");

        let loaded = storage
            .update_permanent_keyshares(&full_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &full_keyset.keyshares());
    }

    /// Import keyshares into KeyshareStorage with an existing share in permanent storage.
    /// Ensure import fails if the existing keyshare is different from the backup keyshare.
    /// Ensure we don't change the KeyshareStorage
    #[tokio::test]
    async fn test_import_backup_failure_existing_shares_permanent() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let (keyshare, alternate_keyshare) = generate_dummy_keyshares(epoch_id, 1, 0, &mut rng);
        // ensure that the keyshares are different
        assert!(alternate_keyshare.data != keyshare.data);
        // ensure that the keyshares are for the same public key
        assert_eq!(
            alternate_keyshare.public_key().unwrap(),
            keyshare.public_key().unwrap()
        );
        let keyset = KeysetBuilder::from_keyshares(epoch_id, &[keyshare.clone()]);

        // populate the key storage with the alternate keyshare
        let (mut storage, _tempdir) = generate_key_storage().await;
        let mut expected = KeysetBuilder::from_keyshares(epoch_id, &[]);
        populate_permanent_keystore(alternate_keyshare, &mut expected, &mut storage).await;

        let res = storage
            .import_backup(keyset.keyshares().to_vec(), &keyset.keyset())
            .await;
        let _ = res.expect_err("Backup import should fail with mismatched permanent share");

        let loaded = storage
            .update_permanent_keyshares(&expected.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &expected.keyshares());
    }

    /// Import keyshares into KeyshareStorage with an existing, matching share in temporary storage.
    /// Ensure we import the missing share from backup.
    #[tokio::test]
    async fn test_import_backup_success_existing_shares_temporary() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_1 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);

        let expected = KeysetBuilder::from_keyshares(epoch_id, &[key_1.clone(), key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        storage
            .start_generating_key(&[], key_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1.clone())
            .await
            .unwrap();

        storage
            .import_backup(expected.keyshares().to_vec(), &expected.keyset())
            .await
            .expect("Backup import should succeed with matching temporary shares");

        let loaded = storage
            .update_permanent_keyshares(&expected.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &expected.keyshares());
    }

    /// Import keyshares into KeyshareStorage with an existing share in temporary storage.
    /// Ensure import fails if the existing keyshare is different from the backup keyshare.
    /// Ensure we don't change the KeyshareStorage.
    #[tokio::test]
    async fn test_import_backup_failure_existing_shares_temporary() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let (key_1, key_1_alternate) = generate_dummy_keyshares(epoch_id, 1, 0, &mut rng);
        // ensure that the keyshares are different
        assert!(key_1_alternate.data != key_1.data);
        // ensure that the keyshares are for the same public key
        assert_eq!(
            key_1_alternate.public_key().unwrap(),
            key_1.public_key().unwrap()
        );
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let keyset_1 = KeysetBuilder::from_keyshares(epoch_id, &[key_1, key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        storage
            .start_generating_key(&[], key_1_alternate.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1_alternate.clone())
            .await
            .unwrap();
        let expected_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1_alternate]);

        let _ = storage
            .import_backup(keyset_1.keyshares().to_vec(), &keyset_1.keyset())
            .await
            .expect_err("Backup import should fail with mismatched temporary share");

        let _ = storage
            .update_permanent_keyshares(&keyset_1.keyset())
            .await
            .expect_err("Permanent update should fail for mismatched backup");

        let loaded = storage
            .update_permanent_keyshares(&expected_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &expected_keyset.keyshares());
    }

    /// Import keyshares into KeyshareStorage that has an existing share from a previous epoch.
    #[tokio::test]
    async fn test_import_backup_success_basic_previous_epoch() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let previous_epoch = 0;
        let epoch_id = 1;
        let (current_key_1, previous_key_1) = generate_dummy_keyshares(epoch_id, 1, 0, &mut rng);
        // ensure that the keyshares are different
        assert!(previous_key_1.data != current_key_1.data);
        // ensure that the keyshares are for the same public key
        assert_eq!(
            previous_key_1.public_key().unwrap(),
            current_key_1.public_key().unwrap()
        );

        let previous_key_1 = Keyshare {
            key_id: KeyEventId::new(
                EpochId::new(previous_epoch),
                DomainId(1),
                AttemptId::new().next(),
            ),
            data: previous_key_1.data,
        };

        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let current_keyset = KeysetBuilder::from_keyshares(epoch_id, &[current_key_1, key_2]);

        let (mut storage, _tempdir) = generate_key_storage().await;

        // Populate a valid keyshare for previous epoch in permanent storage.
        let mut previous_keyset = KeysetBuilder::from_keyshares(previous_epoch, &[]);
        populate_permanent_keystore(previous_key_1, &mut previous_keyset, &mut storage).await;

        storage
            .import_backup(
                current_keyset.keyshares().to_vec(),
                &current_keyset.keyset(),
            )
            .await
            .expect("Backup import should succeed with valid previous-epoch data");

        let loaded = storage
            .update_permanent_keyshares(&current_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &current_keyset.keyshares());
    }

    /// Import keyshares into KeyshareStorage that has an existing share from a previous epoch.
    /// Ensure import fails if the public key of the previous epoch is different.
    #[tokio::test]
    async fn test_import_backup_failure_basic_previous_epoch() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let previous_epoch = 0;

        // Populate share for a different public key for the previous epoch in permanent storage.
        let (mut storage, _tempdir) = generate_key_storage().await;
        let mut previous_keyset = KeysetBuilder::from_keyshares(previous_epoch, &[]);
        let prevous_key = generate_dummy_keyshare(previous_epoch, 1, 8, &mut rng);
        populate_permanent_keystore(prevous_key, &mut previous_keyset, &mut storage).await;

        let epoch_id = 1;
        let dummy_key = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let dummy_keyset = KeysetBuilder::from_keyshares(epoch_id, &[dummy_key.clone()]);

        let _ = storage
            .import_backup(dummy_keyset.keyshares().to_vec(), &dummy_keyset.keyset())
            .await
            .expect_err("Backup import should fail with mismatched previous-epoch key");

        let _ = storage
            .update_permanent_keyshares(&dummy_keyset.keyset())
            .await
            .expect_err("Permanent update should fail for mismatched previous-epoch key");
        let loaded = storage
            .update_permanent_keyshares(&previous_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &previous_keyset.keyshares());
    }

    async fn assert_no_keyshares_for_epoch(epoch_id: u64, keyshare_storage: &KeyshareStorage) {
        let empty_keyset = KeysetBuilder::from_keyshares(epoch_id, &[]);
        let loaded = keyshare_storage
            .get_keyshares(&empty_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &empty_keyset.keyshares());
    }

    /// Ensure import fails if there is a mismatch between the proposed keyset and keyshares
    /// case: same key id, different public keys
    #[tokio::test]
    async fn test_import_backup_failure_inconsistent_backup_public_keys() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let keyset = KeysetBuilder::from_keyshares(epoch_id, &[key]);

        let dummy_key = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let dummy_keyset = KeysetBuilder::from_keyshares(epoch_id, &[dummy_key]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        let _ = storage
            .import_backup(keyset.keyshares().to_vec(), &dummy_keyset.keyset())
            .await
            .expect_err("Backup import should fail with inconsistent public keys");
        let _ = storage
            .update_permanent_keyshares(&keyset.keyset())
            .await
            .expect_err("Permanent update should fail after inconsistent backup");

        assert_no_keyshares_for_epoch(epoch_id, &storage).await;
    }

    /// Ensure import fails if there is a mismatch between the proposed keyset and keyshares
    /// case: backup is missing a keyshare
    #[tokio::test]
    async fn test_import_backup_failure_inconsistent_backup_missing_keyshare() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_1_epoch_1 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let partial_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1_epoch_1.clone()]);

        let key_2_epoch_1 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let full_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1_epoch_1, key_2_epoch_1]);

        let (mut storage, _tempdir) = generate_key_storage().await;

        let _ = storage
            .import_backup(partial_keyset.keyshares().to_vec(), &full_keyset.keyset())
            .await
            .expect_err("Backup import should fail when a keyshare is missing");

        let _ = storage
            .update_permanent_keyshares(&partial_keyset.keyset())
            .await
            .expect_err("Permanent update should fail after missing-keyshare backup");

        assert_no_keyshares_for_epoch(epoch_id, &storage).await;
    }

    /// Ensure import fails if there is a mismatch between the proposed keyset and keyshares
    /// case: backup has an extra keyshare
    #[tokio::test]
    async fn test_import_backup_failure_inconsistent_backup_extra_keyshare() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;

        let key_1_epoch_1 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let partial_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1_epoch_1.clone()]);

        let key_2_epoch_1 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let full_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key_1_epoch_1, key_2_epoch_1]);

        let (mut storage, _tempdir) = generate_key_storage().await;
        let _ = storage
            .import_backup(full_keyset.keyshares().to_vec(), &partial_keyset.keyset())
            .await
            .expect_err("Backup import should fail when an extra keyshare is present");

        let _ = storage
            .update_permanent_keyshares(&partial_keyset.keyset())
            .await
            .expect_err("Permanent update should fail after extra-keyshare backup");
        assert_no_keyshares_for_epoch(epoch_id, &storage).await;
    }

    /// Ensure import fails if it has less keys than wat is stored in the KeyshareStorage.
    #[tokio::test]
    async fn test_import_backup_failure_inconsistent_backup_missing_shares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;

        let mut expected_keyset = KeysetBuilder::from_keyshares(epoch_id, &[]);
        let (mut storage_2, _tempdir) = generate_key_storage().await;

        let key = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        populate_permanent_keystore(key.clone(), &mut expected_keyset, &mut storage_2).await;
        let key_2 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        populate_permanent_keystore(key_2, &mut expected_keyset, &mut storage_2).await;

        let partial_keyset = KeysetBuilder::from_keyshares(epoch_id, &[key]);

        let _ = storage_2
            .import_backup(
                partial_keyset.keyshares().to_vec(),
                &expected_keyset.keyset(),
            )
            .await
            .expect_err("Backup import should fail when backup has too few shares");

        let _ = storage_2
            .update_permanent_keyshares(&partial_keyset.keyset())
            .await
            .expect_err("Permanent update should fail after incomplete backup");
        let loaded = storage_2
            .update_permanent_keyshares(&expected_keyset.keyset())
            .await
            .unwrap();
        assert_eq!(&loaded, &expected_keyset.keyshares());
    }

    #[tokio::test]
    async fn test_get_keyshares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_0 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let key_1 = generate_dummy_keyshare(epoch_id, 2, 3, &mut rng);
        let mut keyset = KeysetBuilder::from_keyshares(epoch_id, &[]);
        let (mut storage, _tempdir) = generate_key_storage().await;
        populate_permanent_keystore(key_1.clone(), &mut keyset, &mut storage).await;
        let keyset0 = KeysetBuilder::from_keyshares(epoch_id, &[key_0]).keyset();

        let _ = storage
            .get_keyshares(&keyset0)
            .await
            .expect_err("Missing keyset should return an error");

        let keyset1 = KeysetBuilder::from_keyshares(epoch_id, &[key_1.clone()]).keyset();

        assert_eq!(storage.get_keyshares(&keyset1).await.unwrap(), vec![key_1]);
    }

    #[tokio::test]
    async fn test_get_keyshare_from_temporary() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_0 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let (mut storage, _tempdir) = generate_key_storage().await;
        storage
            .start_generating_key(&[], key_0.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_0.clone())
            .await
            .unwrap();

        let keyset0 = KeysetBuilder::from_keyshares(epoch_id, &[key_0.clone()]).keyset();

        // At this point keyset0 must be in temporary storage
        assert_eq!(
            storage.get_keyshares(&keyset0).await.unwrap(),
            vec![key_0.clone()]
        );

        // Now we move keyset0 to permanent storage
        let loaded1 = storage.update_permanent_keyshares(&keyset0).await.unwrap();
        assert_eq!(&loaded1, &vec![key_0]);
    }

    #[tokio::test]
    async fn test_get_keyshare_does_not_mutate_state() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let epoch_id = 1;
        let key_0 = generate_dummy_keyshare(epoch_id, 1, 0, &mut rng);
        let key_1 = generate_dummy_keyshare(epoch_id, 2, 1, &mut rng);
        let keyset0 = KeysetBuilder::from_keyshares(epoch_id, &[key_0.clone()]);
        let keyset1 = KeysetBuilder::from_keyshares(epoch_id, &[key_0.clone(), key_1.clone()]);
        let keyset2 = KeysetBuilder::from_keyshares(epoch_id, &[key_1.clone(), key_0.clone()]);
        let (mut storage, _tempdir) = generate_key_storage().await;
        storage
            .start_generating_key(&[], key_0.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_0.clone())
            .await
            .unwrap();
        storage
            .start_generating_key(&keyset0.generated(), key_1.key_id)
            .await
            .unwrap()
            .commit_keyshare(key_1.clone())
            .await
            .unwrap();
        storage
            .update_permanent_keyshares(&keyset0.keyset())
            .await
            .unwrap();

        let key_shares_permanent_storage =
            storage.permanent.load().await.unwrap().unwrap().keyshares;
        let key_share_in_temporary_storage = storage
            .temporary
            .load_keyshare(key_1.key_id)
            .await
            .unwrap()
            .unwrap();

        // Get correct keyshares from permanent
        assert_eq!(
            storage.get_keyshares(&keyset0.keyset()).await.unwrap(),
            vec![key_0.clone()]
        );
        // Get correct keyshares from permanent and temporary
        assert_eq!(
            storage.get_keyshares(&keyset1.keyset()).await.unwrap(),
            vec![key_0.clone(), key_1.clone()]
        );
        // A call that fails
        let _ = storage
            .get_keyshares(&keyset2.keyset())
            .await
            .expect_err("Reordered keyset should not be found");

        let final_key_shares_permanent_storage =
            storage.permanent.load().await.unwrap().unwrap().keyshares;
        let final_key_share_in_temporary_storage = storage
            .temporary
            .load_keyshare(key_1.key_id)
            .await
            .unwrap()
            .unwrap();

        // Permanent storage did not change
        assert_eq!(
            final_key_shares_permanent_storage,
            key_shares_permanent_storage
        );
        // This key remains in temporary storage
        assert_eq!(
            final_key_share_in_temporary_storage,
            key_share_in_temporary_storage
        );
    }
}
