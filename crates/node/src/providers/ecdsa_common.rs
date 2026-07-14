//! Plumbing shared by the two ECDSA providers (cait-sith [`EcdsaSignatureProvider`] and
//! Damgård-et-al [`RobustEcdsaSignatureProvider`], both over secp256k1). Both keep the same
//! per-domain keyshare + presignature store; only the presignature payload `P` and the surrounding
//! protocol differ, so the storage and per-domain scaffolding are generic over `P` here.

use crate::assets::DistributedAssetStorage;
use crate::db::SecretDB;
use crate::network::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::providers::{DomainKeyshare, HasParticipants};
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_time::Clock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::ecdsa::{KeygenOutput, Secp256K1Sha256};

/// A stored presignature together with the participants that produced it, so the store can drop it
/// once any of those participants goes offline. Generic over the presignature payload `P`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutputWithParticipants<P> {
    pub presignature: P,
    pub participants: Vec<ParticipantId>,
}

impl<P> HasParticipants for PresignOutputWithParticipants<P> {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        self.participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

/// Per-domain presignature store, keyed on disk by `domain_id` under [`crate::db::DBCol::Presignature`].
#[derive(derive_more::Deref)]
pub struct PresignatureStorage<P>(DistributedAssetStorage<PresignOutputWithParticipants<P>>)
where
    P: Serialize + DeserializeOwned + Send + 'static;

impl<P> PresignatureStorage<P>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        client: &Arc<MeshNetworkClient>,
        domain_id: DomainId,
    ) -> anyhow::Result<Self> {
        Ok(Self(DistributedAssetStorage::<
            PresignOutputWithParticipants<P>,
        >::new(
            clock,
            db,
            crate::db::DBCol::Presignature,
            domain_id.0.to_be_bytes().to_vec(),
            client.my_participant_id(),
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            active_participants_query(client),
        )?))
    }
}

/// A domain's [`DomainKeyshare`] material plus a presignature store, which is runtime state the
/// coordinator can't provide and so is built here.
pub struct EcdsaKeyshare<P>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    pub keygen_output: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage<P>>,
    pub reconstruction_threshold: ReconstructionThreshold,
}

// Manual `Clone` so callers don't need `P: Clone` — every field is `Clone` regardless of `P`.
impl<P> Clone for EcdsaKeyshare<P>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            keygen_output: self.keygen_output.clone(),
            presignature_store: self.presignature_store.clone(),
            reconstruction_threshold: self.reconstruction_threshold,
        }
    }
}

/// The "are all these participants still alive?" query both the presignature and triple stores use.
pub fn active_participants_query(
    client: &Arc<MeshNetworkClient>,
) -> Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync> {
    let network_client = client.clone();
    Arc::new(move || network_client.all_alive_participant_ids())
}

/// Attaches a freshly-created presignature store to each domain's [`DomainKeyshare`].
pub fn build_keyshares<P>(
    clock: &Clock,
    db: &Arc<SecretDB>,
    client: &Arc<MeshNetworkClient>,
    keyshares: HashMap<DomainId, DomainKeyshare<Secp256K1Sha256>>,
) -> anyhow::Result<HashMap<DomainId, EcdsaKeyshare<P>>>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    let mut result = HashMap::new();
    for (domain_id, keyshare) in keyshares {
        let presignature_store = Arc::new(PresignatureStorage::new(
            clock.clone(),
            db.clone(),
            client,
            domain_id,
        )?);
        result.insert(
            domain_id,
            EcdsaKeyshare {
                keygen_output: keyshare.keygen_output,
                presignature_store,
                reconstruction_threshold: keyshare.reconstruction_threshold,
            },
        );
    }
    Ok(result)
}

/// Looks up a domain's keyshare, cloning it out of the map.
pub fn lookup_keyshare<P>(
    keyshares: &HashMap<DomainId, EcdsaKeyshare<P>>,
    domain_id: DomainId,
) -> anyhow::Result<EcdsaKeyshare<P>>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    keyshares
        .get(&domain_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{DomainKeyshare, build_keyshares};
    use crate::db::SecretDB;
    use crate::network::testing::run_test_clients;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_primitives::ReconstructionThreshold;
    use mpc_primitives::domain::DomainId;
    use near_time::Clock;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use threshold_signatures::ecdsa::KeygenOutput;
    use threshold_signatures::frost_secp256k1::Secp256K1Sha256;
    use threshold_signatures::test_utils::{generate_participants, run_keygen};

    fn dummy_keygen_output() -> KeygenOutput {
        let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
        run_keygen::<Secp256K1Sha256, _>(&generate_participants(2), 2usize, &mut rng)
            .into_iter()
            .next()
            .unwrap()
            .1
    }

    // Directly asserts the plumbing that `multidomain_with_distinct_reconstruction_thresholds`
    // only checks indirectly (by running a full multi-node signing round): each domain must keep
    // its OWN reconstruction threshold, never a single shared/governance value.
    #[tokio::test]
    async fn build_keyshares__should_pair_each_domain_with_its_own_reconstruction_threshold() {
        start_root_task_with_periodic_dump(async move {
            run_test_clients(
                into_participant_ids(&generate_participants(2)),
                |client, _channel_receiver| async move {
                    // Given two domains configured with distinct reconstruction thresholds
                    let low = DomainId(0);
                    let high = DomainId(1);
                    let keygen_output = dummy_keygen_output();
                    let keyshares = HashMap::from([
                        (
                            low,
                            DomainKeyshare::new(
                                keygen_output.clone(),
                                ReconstructionThreshold::new(2),
                            ),
                        ),
                        (
                            high,
                            DomainKeyshare::new(keygen_output, ReconstructionThreshold::new(3)),
                        ),
                    ]);
                    let dir = tempfile::tempdir().unwrap();
                    let db = SecretDB::new(dir.path(), [1; 16]).unwrap();

                    // When
                    let keyshares =
                        build_keyshares::<Vec<u8>>(&Clock::real(), &db, &client, keyshares)
                            .unwrap();

                    // Then each domain keeps the threshold it was configured with
                    assert_eq!(
                        keyshares[&low].reconstruction_threshold,
                        ReconstructionThreshold::new(2)
                    );
                    assert_eq!(
                        keyshares[&high].reconstruction_threshold,
                        ReconstructionThreshold::new(3)
                    );
                    Ok(())
                },
            )
            .await
            .unwrap();
        })
        .await;
    }
}
