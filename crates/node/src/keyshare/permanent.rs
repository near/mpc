use super::Keyshare;
use anyhow::Context;
use k256::{AffinePoint, Scalar};
use mpc_contract::primitives::key_state::EpochId;
use mpc_primitives::domain::DomainId;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The single object we persist to permanent key storage.
/// Corresponds to a Keyset in the contract side (i.e. one keyshare per domain).
///
/// Keyshares are stored in a `NonEmptyBTreeMap<DomainId, Keyshare>`, which enforces
/// ordering by `DomainId`, uniqueness, and non-emptiness at the type level.
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
    pub fn from_legacy(legacy: &LegacyRootKeyshareData) -> Self {
        let keyshare = Keyshare::from_legacy(legacy);
        let keyshares = NonEmptyBTreeMap::new(keyshare.key_id.domain_id, keyshare);
        Self {
            epoch_id: EpochId::new(legacy.epoch),
            keyshares,
        }
    }

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
}

/// Backend for storing the permanent keyshare data.
#[async_trait::async_trait]
pub trait PermanentKeyStorageBackend: Send + Sync {
    /// Loads the latest stored data; or None if no data was ever stored.
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Stores the data, making it the latest. The identifier is used for the local backend to write
    /// the data to a separate file and then linking it to the main file (acting as a backup
    /// mechanism).
    async fn store(&self, data: &[u8], identifier: &str) -> anyhow::Result<()>;
}

/// Manages permanent keyshares. These are the keyshares we see from the Running state.
/// When we generate or reshare a key, that key goes into temporary key storage first,
/// and only when we transition to Running do we move it to permanent key storage.
pub struct PermanentKeyStorage {
    backend: Box<dyn PermanentKeyStorageBackend>,
}

impl PermanentKeyStorage {
    pub async fn new(backend: Box<dyn PermanentKeyStorageBackend>) -> anyhow::Result<Self> {
        let ret = Self { backend };

        // Migrate legacy data if necessary.
        let existing_data = ret.backend.load().await?;
        if let Some(data) = existing_data {
            if serde_json::from_slice::<PermanentKeyshareData>(&data).is_err() {
                tracing::info!(
                    "Existing permanent keyshare data is not in the expected format, attempting to migrate..."
                );
                let legacy_data = serde_json::from_slice::<LegacyRootKeyshareData>(&data)?;
                let new_data = PermanentKeyshareData::from_legacy(&legacy_data);
                ret.store_unchecked(&new_data).await?;
            }
        }
        Ok(ret)
    }

    pub async fn load(&self) -> anyhow::Result<Option<PermanentKeyshareData>> {
        let data = self.backend.load().await?;
        Ok(data.map(|data| serde_json::from_slice(&data)).transpose()?)
    }

    #[expect(rustdoc::private_intra_doc_links)]
    /// Attempts to store the given [`PermanentKeyshareData`] in persistent storage,
    /// replacing existing data only if the new keyset is considered valid.
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
    /// Only if all checks succeed will the new keyset be stored via [`Self::store_unchecked`].
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
        self.store_unchecked(keyshare_data).await
    }

    async fn store_unchecked(&self, keyshare_data: &PermanentKeyshareData) -> anyhow::Result<()> {
        let data_json = serde_json::to_vec(keyshare_data)?;
        let identifier = format!(
            "epoch_{}_with_{}_domains",
            keyshare_data.epoch_id().get(),
            keyshare_data.keyshares().len()
        );
        self.backend.store(&data_json, &identifier).await
    }
}

/// Old version of the permanent keyshare data, for migration only.
#[derive(Clone, Serialize, Deserialize)]
pub struct LegacyRootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

#[cfg(test)]
mod tests {
    use super::PermanentKeyshareData;
    use crate::keyshare::local::LocalPermanentKeyStorageBackend;
    use crate::keyshare::permanent::{
        LegacyRootKeyshareData, PermanentKeyStorage, PermanentKeyStorageBackend,
    };
    use crate::keyshare::test_utils::{
        generate_dummy_keyshare, generate_dummy_keyshares, make_key_id, KeysetBuilder,
    };
    use crate::keyshare::{Keyshare, KeyshareData};
    use k256::elliptic_curve::Field;
    use k256::{AffinePoint, Scalar};
    use mpc_contract::primitives::key_state::EpochId;
    use rand::SeedableRng as _;
    use threshold_signatures::frost_secp256k1::keys::SigningShare;
    use threshold_signatures::frost_secp256k1::VerifyingKey;

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
    async fn test_legacy_migration() {
        let temp = tempfile::tempdir().unwrap();
        let encryption_key = [2; 16];
        let backend =
            LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), encryption_key)
                .await
                .unwrap();
        // Write a legacy keyshare.
        let private_share = Scalar::random(&mut rand::thread_rng());
        let public_key = AffinePoint::GENERATOR * private_share;
        let legacy_data = LegacyRootKeyshareData {
            epoch: 1,
            private_share,
            // Do some computation to get non-identity public key
            public_key: public_key.to_affine(),
        };
        let legacy_data_json = serde_json::to_vec(&legacy_data).unwrap();
        let identifier = "whatever";
        backend.store(&legacy_data_json, identifier).await.unwrap();

        // Make the storage. The storage should upgrade the legacy keyshare to the new format.
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded.epoch_id().get(), 1);
        assert_eq!(loaded.keyshares().len(), 1);
        let keyshare = loaded.keyshares().values().next().unwrap();
        assert_eq!(keyshare.key_id.epoch_id.get(), 1);
        assert_eq!(keyshare.key_id.domain_id.0, 0);
        assert_eq!(keyshare.key_id.attempt_id.get(), 0);
        assert_eq!(
            keyshare.data,
            KeyshareData::Secp256k1(threshold_signatures::ecdsa::KeygenOutput {
                private_share: SigningShare::new(legacy_data.private_share),
                public_key: VerifyingKey::new(legacy_data.public_key.into()),
            })
        );
    }
}
