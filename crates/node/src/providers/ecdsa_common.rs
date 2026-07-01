//! Plumbing shared by the two ECDSA providers (cait-sith [`EcdsaSignatureProvider`] and
//! Damgård-et-al [`RobustEcdsaSignatureProvider`], both over secp256k1). Both keep the same
//! per-domain keyshare + presignature store; only the presignature payload `P` and the surrounding
//! protocol differ, so the storage and per-domain scaffolding are generic over `P` here.

use crate::assets::DistributedAssetStorage;
use crate::db::SecretDB;
use crate::network::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::providers::HasParticipants;
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_time::Clock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::ecdsa::KeygenOutput;

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

/// Everything a secp256k1 provider keeps per signing domain.
pub struct PerDomainData<P>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    pub keyshare: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage<P>>,
    /// Per-domain reconstruction threshold `t`, the source of truth for this domain's
    /// keygen/presign/sign.
    pub reconstruction_threshold: ReconstructionThreshold,
}

// Manual `Clone` so callers don't need `P: Clone` — every field is `Clone` regardless of `P`.
impl<P> Clone for PerDomainData<P>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            keyshare: self.keyshare.clone(),
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

/// Builds the per-domain map shared by both secp256k1 providers: one presignature store per domain,
/// each paired with its keyshare and reconstruction threshold.
pub fn build_per_domain_data<P>(
    clock: &Clock,
    db: &Arc<SecretDB>,
    client: &Arc<MeshNetworkClient>,
    keyshares: HashMap<DomainId, KeygenOutput>,
    thresholds: &HashMap<DomainId, ReconstructionThreshold>,
) -> anyhow::Result<HashMap<DomainId, PerDomainData<P>>>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    let mut per_domain_data = HashMap::new();
    for (domain_id, keyshare) in keyshares {
        let reconstruction_threshold = *thresholds.get(&domain_id).ok_or_else(|| {
            anyhow::anyhow!("No reconstruction threshold for domain {:?}", domain_id)
        })?;
        let presignature_store = Arc::new(PresignatureStorage::new(
            clock.clone(),
            db.clone(),
            client,
            domain_id,
        )?);
        per_domain_data.insert(
            domain_id,
            PerDomainData {
                keyshare,
                presignature_store,
                reconstruction_threshold,
            },
        );
    }
    Ok(per_domain_data)
}

/// Looks up a domain's data, cloning it out of the map.
pub fn lookup_domain_data<P>(
    per_domain_data: &HashMap<DomainId, PerDomainData<P>>,
    domain_id: DomainId,
) -> anyhow::Result<PerDomainData<P>>
where
    P: Serialize + DeserializeOwned + Send + 'static,
{
    per_domain_data
        .get(&domain_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
}
