use super::{Keyshare, to_json_zeroizing};
use anyhow::Context;
use mpc_primitives::{EpochId, domain::DomainId};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The single object we persist to permanent key storage.
/// Corresponds to a Keyset in the contract side (i.e. one keyshare per domain).
///
/// Keyshares are stored in a `NonEmptyBTreeMap<DomainId, Keyshare>`, which enforces
/// ordering by [`DomainId`], uniqueness, and non-emptiness at the type level.
///
/// Serialization format is backwards-compatible: keyshares are serialized as a
/// JSON array (`Vec<Keyshare>`) and deserialized from the same format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    try_from = "PermanentKeyshareDataSerde",
    into = "PermanentKeyshareDataSerde"
)]
pub struct PermanentKeyshareData {
    epoch_id: EpochId,
    keyshares: NonEmptyBTreeMap<DomainId, Keyshare>,
}

/// Serde helper for backwards-compatible serialization/deserialization.
/// Persisted data stores keyshares as a JSON array (`Vec<Keyshare>`).
#[derive(Serialize, Deserialize)]
struct PermanentKeyshareDataSerde {
    epoch_id: EpochId,
    keyshares: Vec<Keyshare>,
}

impl TryFrom<PermanentKeyshareDataSerde> for PermanentKeyshareData {
    type Error = anyhow::Error;

    fn try_from(serde_repr: PermanentKeyshareDataSerde) -> Result<Self, Self::Error> {
        Self::new(serde_repr.epoch_id, serde_repr.keyshares)
    }
}

impl From<PermanentKeyshareData> for PermanentKeyshareDataSerde {
    fn from(data: PermanentKeyshareData) -> Self {
        let keyshares: BTreeMap<DomainId, Keyshare> = data.keyshares.into();
        PermanentKeyshareDataSerde {
            epoch_id: data.epoch_id,
            keyshares: keyshares.into_values().collect(),
        }
    }
}

impl PermanentKeyshareData {
    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub fn keyshares(&self) -> &BTreeMap<DomainId, Keyshare> {
        &self.keyshares
    }

    pub fn keyshares_vec(&self) -> Vec<Keyshare> {
        self.keyshares.values().cloned().collect()
    }

    pub fn keyshare_by_domain_id(&self, domain_id: DomainId) -> Option<&Keyshare> {
        self.keyshares.get(&domain_id)
    }

    pub fn new(epoch_id: EpochId, keyshares: Vec<Keyshare>) -> anyhow::Result<Self> {
        let mut map = BTreeMap::new();
        for keyshare in keyshares {
            if keyshare.key_id.epoch_id != epoch_id {
                anyhow::bail!(
                    "Inconsistent epoch id. Keyshare has epoch id {}, but expected {}",
                    keyshare.key_id.epoch_id,
                    epoch_id
                );
            }
            let domain_id = keyshare.key_id.domain_id;
            if map.insert(domain_id, keyshare).is_some() {
                anyhow::bail!("Duplicate domain_id {:?} in keyshares", domain_id);
            }
        }
        let keyshares = map
            .try_into()
            .map_err(|_| anyhow::anyhow!("Keyshares must not be empty"))?;
        Ok(PermanentKeyshareData {
            epoch_id,
            keyshares,
        })
    }

    fn storage_identifier(&self) -> String {
        storage_identifier(self.epoch_id, self.keyshares().len())
    }
}

/// Identifier under which [`PermanentKeyStorage`] stores a keyset of `num_domains` domains in
/// `epoch_id`.
pub(crate) fn storage_identifier(epoch_id: EpochId, num_domains: usize) -> String {
    format!("epoch_{}_with_{num_domains}_domains", epoch_id.get())
}

/// Backend for storing the permanent keyshare data.
#[async_trait::async_trait]
pub trait PermanentKeyStorageBackend: Send + Sync {
    /// Loads the latest stored data; or None if no data was ever stored.
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Stores the data, making it the latest. The local backend writes the data to a file named
    /// after `identifier` and then points the main file at it.
    async fn store(&self, data: &[u8], identifier: &str) -> anyhow::Result<()>;
    /// Deletes the data stored under any identifier other than `identifier`. Never changes what
    /// [`Self::load`] returns.
    async fn delete_all_except(&self, identifier: &str) -> anyhow::Result<()>;
}

/// Manages permanent keyshares. These are the keyshares we see from the Running state.
/// When we generate or reshare a key, that key goes into temporary key storage first,
/// and only when we transition to Running do we move it to permanent key storage.
///
/// Only the latest keyset is kept: storing a keyset deletes the ones stored before it, since a
/// share of an earlier epoch still counts towards reconstructing the key.
pub struct PermanentKeyStorage {
    backend: Box<dyn PermanentKeyStorageBackend>,
}

impl PermanentKeyStorage {
    pub async fn new(backend: Box<dyn PermanentKeyStorageBackend>) -> anyhow::Result<Self> {
        let storage = Self { backend };
        // Fails at startup, not at the first key use, on keyshares that cannot be decrypted or parsed.
        storage
            .load()
            .await
            .context("Loading the existing permanent keyshares")?;
        Ok(storage)
    }

    pub async fn load(&self) -> anyhow::Result<Option<PermanentKeyshareData>> {
        let data = self.backend.load().await?.map(Zeroizing::new);
        Ok(data.map(|data| serde_json::from_slice(&data)).transpose()?)
    }

    /// Deletes the keysets that the stored keyset replaced. Deletes nothing when no keyset is
    /// stored.
    pub async fn delete_replaced(&self) -> anyhow::Result<()> {
        // Without a stored keyset, the files may be the only copies left.
        let Some(stored) = self.load().await? else {
            return Ok(());
        };
        self.backend
            .delete_all_except(&stored.storage_identifier())
            .await
    }

    /// Attempts to store the given [`PermanentKeyshareData`] in persistent storage,
    /// replacing existing data only if the new keyset is considered valid.
    ///
    /// The replaced keysets are deleted, so only call this with the keyset the contract is
    /// Running in, or Resharing from.
    ///
    /// Validation is performed against the latest stored keyset to prevent
    /// accidental downgrades or mismatches.
    ///
    /// # Validation rules
    /// The new keyset is **rejected** for any of the following reasons:
    /// - It has a **lower epoch id** than the existing keyset.
    /// - It does not contain keshares for existing domains and public keys.
    /// - If has the **same epoch id** as the existing keyset, but **does not** extend the keyset.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] if validation fails or if persistence fails.
    ///
    /// # Returns
    /// * `Ok(())` if the keyset was successfully stored.
    /// * `Err(anyhow::Error)` otherwise.
    pub async fn store(&self, keyshare_data: &PermanentKeyshareData) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            let existing_keyset_is_more_recent =
                existing.epoch_id().get() > keyshare_data.epoch_id().get();
            if existing_keyset_is_more_recent {
                anyhow::bail!(
                    "Refusing to overwrite existing permanent keyshares of epoch {} with new permanent keyshares of older epoch {}",
                    existing.epoch_id().get(),
                    keyshare_data.epoch_id().get(),
                );
            }
            let existing_keset_has_more_domains =
                existing.keyshares().len() > keyshare_data.keyshares().len();
            if existing_keset_has_more_domains {
                anyhow::bail!(
                    "Refusing to overwrite existing permanent keyshares for {} domains with new permanent keyshares for fewer domains {}",
                    existing.keyshares().len(),
                    keyshare_data.keyshares().len()
                );
            }
            let is_same_epoch_id = existing.epoch_id().get() == keyshare_data.epoch_id().get();
            let does_not_extend_keyset =
                existing.keyshares().len() >= keyshare_data.keyshares().len();
            if is_same_epoch_id && does_not_extend_keyset {
                anyhow::bail!(
                    "Refusing to overwrite existing permanent keyshares of epoch {} with new permanent keyshares of same epoch but equal number of domains",
                    existing.epoch_id().get(),
                );
            }
            for (domain_id, existing_keyshare) in existing.keyshares() {
                let Some(new_keyshare) = keyshare_data.keyshares().get(domain_id) else {
                    anyhow::bail!(
                        "Refusing to overwrite existing permanent keyshare for domain id {:?} with new permanent keyshares missing that domain",
                        existing_keyshare.key_id,
                    );
                };

                let key_ids_match = existing_keyshare.key_id == new_keyshare.key_id;
                if is_same_epoch_id && !key_ids_match {
                    anyhow::bail!(
                        "Refusing to overwrite existing permanent keyshare of key id {:?} with new permanent keyshare of different key id {:?} for the same epoch.",
                        existing_keyshare.key_id,
                        new_keyshare.key_id
                    );
                }

                let public_keys_match =
                    existing_keyshare.public_key()? == new_keyshare.public_key()?;
                if !public_keys_match {
                    anyhow::bail!(
                        "Refusing to overwrite existing permanent keyshare of key id {:?} with new permanent keyshare of same domin id  {:?} but different public key.\
                            Existing public key: {:?}, new public key: {:?}",
                        existing_keyshare.key_id,
                        new_keyshare.key_id,
                        existing_keyshare.public_key(),
                        new_keyshare.public_key()
                    );
                }
            }
        }
        let identifier = keyshare_data.storage_identifier();
        self.backend
            .store(&to_json_zeroizing(keyshare_data)?, &identifier)
            .await?;
        // The new keyset is stored either way, so a failed deletion does not fail the store.
        if let Err(err) = self.backend.delete_all_except(&identifier).await {
            tracing::error!(?err, "failed to delete the replaced permanent keyshares");
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::PermanentKeyshareData;
    use crate::home_paths::permanent_key_link;
    use crate::keyshare::Keyshare;
    use crate::keyshare::local::LocalPermanentKeyStorageBackend;
    use crate::keyshare::permanent::{PermanentKeyStorage, PermanentKeyStorageBackend};
    use crate::keyshare::test_utils::{
        KeysetBuilder, generate_dummy_keyshare, generate_dummy_keyshares, list_permanent_key_files,
        make_key_id,
    };
    use k256::{AffinePoint, Scalar};
    use mpc_primitives::EpochId;
    use rand::SeedableRng as _;
    use rstest::rstest;

    #[tokio::test]
    async fn test_load_store() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let temp = tempfile::tempdir().unwrap();
        let encryption_key = [2; 16];
        let backend =
            LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), encryption_key)
                .await
                .unwrap();
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();
        assert!(storage.load().await.unwrap().is_none());

        let (key_1, key_1_alternate) = generate_dummy_keyshares(1, 0, 1, &mut rng);
        let (key_2, key_2_alternate) = generate_dummy_keyshares(1, 2, 4, &mut rng);
        let keys = vec![key_1.clone(), key_2];
        let permanent_keyshare = PermanentKeyshareData::new(EpochId::new(1), keys.clone()).unwrap();

        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);

        // Cannot store the same permanent keyshare twice.
        let _ = storage
            .store(&permanent_keyshare)
            .await
            .expect_err("Storing duplicate permanent keyshare should fail");
        // Cannot store current epoch with fewer domains.
        let keys = vec![key_1];
        let permanent_keyshare = KeysetBuilder::from_keyshares(1, &keys).permanent_key_data();
        let _ = storage
            .store(&permanent_keyshare)
            .await
            .expect_err("Storing fewer domains for current epoch should fail");
        // Cannot store older epoch than current.
        let keys = vec![
            Keyshare {
                key_id: make_key_id(0, 0, 1),
                data: key_1_alternate.data.clone(),
            },
            Keyshare {
                key_id: make_key_id(0, 2, 4),
                data: key_2_alternate.data.clone(),
            },
        ];
        let permanent_keyshare = KeysetBuilder::from_keyshares(0, &keys).permanent_key_data();
        let _ = storage
            .store(&permanent_keyshare)
            .await
            .expect_err("Storing an older epoch should fail");

        // Can store newer epoch than current.
        let keys = vec![
            Keyshare {
                key_id: make_key_id(2, 0, 8),
                data: key_1_alternate.data.clone(),
            },
            Keyshare {
                key_id: make_key_id(2, 2, 10),
                data: key_2_alternate.data.clone(),
            },
        ];

        let permanent_keyshare = KeysetBuilder::from_keyshares(2, &keys).permanent_key_data();
        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);

        // Can store current epoch with more domains.
        let mut keys = keys;
        keys.extend(vec![generate_dummy_keyshare(2, 3, 5, &mut rng)]);
        let permanent_keyshare = KeysetBuilder::from_keyshares(2, &keys).permanent_key_data();
        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);
    }

    #[tokio::test]
    async fn permanent_key_storage_new__should_fail_on_legacy_keyshare_format() {
        // Given
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), [2; 16])
            .await
            .unwrap();
        let legacy_keyshare = serde_json::json!({
            "epoch": 1,
            "private_share": Scalar::ONE,
            "public_key": AffinePoint::GENERATOR,
        });
        backend
            .store(&serde_json::to_vec(&legacy_keyshare).unwrap(), "legacy")
            .await
            .unwrap();

        // When
        let result = PermanentKeyStorage::new(Box::new(backend)).await;

        // Then
        assert!(result.is_err());
    }

    #[rstest]
    #[case::next_epoch(keysets_of_consecutive_epochs())]
    #[case::added_domain(keysets_before_and_after_adding_a_domain())]
    #[tokio::test]
    async fn store__should_delete_superseded_keyshare_files(
        #[case] keysets: (PermanentKeyshareData, PermanentKeyshareData),
    ) {
        // Given
        let (older, latest) = keysets;
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), [2; 16])
            .await
            .unwrap();
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();
        storage.store(&older).await.unwrap();

        // When
        storage.store(&latest).await.unwrap();

        // Then
        assert_eq!(
            list_permanent_key_files(temp.path()),
            vec![latest.storage_identifier()]
        );
        assert_eq!(storage.load().await.unwrap().unwrap(), latest);
    }

    fn keysets_of_consecutive_epochs() -> (PermanentKeyshareData, PermanentKeyshareData) {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let (key_epoch_0, other_share) = generate_dummy_keyshares(0, 0, 1, &mut rng);
        let key_epoch_1 = Keyshare {
            key_id: make_key_id(1, 0, 1),
            data: other_share.data,
        };
        (
            KeysetBuilder::from_keyshares(0, &[key_epoch_0]).permanent_key_data(),
            KeysetBuilder::from_keyshares(1, &[key_epoch_1]).permanent_key_data(),
        )
    }

    fn keysets_before_and_after_adding_a_domain() -> (PermanentKeyshareData, PermanentKeyshareData)
    {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let first = generate_dummy_keyshare(0, 0, 1, &mut rng);
        let second = generate_dummy_keyshare(0, 1, 1, &mut rng);
        (
            KeysetBuilder::from_keyshares(0, std::slice::from_ref(&first)).permanent_key_data(),
            KeysetBuilder::from_keyshares(0, &[first, second]).permanent_key_data(),
        )
    }

    #[tokio::test]
    async fn delete_replaced__should_keep_only_the_stored_keyset() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), [2; 16])
            .await
            .unwrap();
        let older = KeysetBuilder::new_populated(0, 1, &mut rng).permanent_key_data();
        let latest = KeysetBuilder::new_populated(1, 1, &mut rng).permanent_key_data();
        for keyset in [&older, &latest] {
            backend
                .store(
                    &serde_json::to_vec(keyset).unwrap(),
                    &keyset.storage_identifier(),
                )
                .await
                .unwrap();
        }
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();

        // When
        storage.delete_replaced().await.unwrap();

        // Then
        assert_eq!(
            list_permanent_key_files(temp.path()),
            vec![latest.storage_identifier()]
        );
        assert_eq!(storage.load().await.unwrap().unwrap(), latest);
    }

    #[tokio::test]
    async fn delete_replaced__should_delete_nothing_without_a_stored_keyset() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), [2; 16])
            .await
            .unwrap();
        let keyset = KeysetBuilder::new_populated(0, 1, &mut rng).permanent_key_data();
        backend
            .store(
                &serde_json::to_vec(&keyset).unwrap(),
                &keyset.storage_identifier(),
            )
            .await
            .unwrap();
        std::fs::remove_file(permanent_key_link(temp.path())).unwrap();
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();

        // When
        storage.delete_replaced().await.unwrap();

        // Then
        assert_eq!(
            list_permanent_key_files(temp.path()),
            vec![keyset.storage_identifier()]
        );
    }
}
