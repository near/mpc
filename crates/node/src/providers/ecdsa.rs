pub mod key_generation;
pub mod key_resharing;
pub mod presign;
pub mod triple;

mod online_presign;
mod sign;

use near_mpc_contract_interface::types::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;

pub use triple::TripleStorage;

use crate::config::{MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId, UniqueId};
use crate::protocol_version::CommunicationProtocols;
use crate::providers::{DomainKeyshare, SignatureProvider, ecdsa_common};
use crate::storage::SignRequestStorage;
use crate::tracking;
use mpc_node_config::ConfigFile;

use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::{KeygenOutput, Secp256K1Sha256, Signature};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::frost_secp256k1::keys::SigningShare;

pub struct EcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    /// Triple stores indexed by signer-set size `t`. Populated at construction
    /// from the set of thresholds this node needs to serve — cait-sith triple
    /// generation always runs with exactly `t` parties, so the full set of
    /// `t`s is known up front and no on-demand creation is needed.
    triple_stores: HashMap<ReconstructionThreshold, Arc<TripleStorage>>,
    sign_request_store: Arc<SignRequestStorage>,
    keyshares: HashMap<DomainId, EcdsaKeyshare>,
}

pub(super) type EcdsaKeyshare = ecdsa_common::EcdsaKeyshare<PresignOutput>;

/// Handshake protocol version that introduced [`EcdsaTaskId::OnlinePresignSignature`].
pub const ONLINE_PRESIGN_MIN_PROTOCOL_VERSION: CommunicationProtocols =
    CommunicationProtocols::Sep2026;

impl EcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, DomainKeyshare<Secp256K1Sha256>>,
    ) -> anyhow::Result<Self> {
        let keyshares = ecdsa_common::build_keyshares(&clock, &db, client.clone(), keyshares)?;

        // cait-sith triple generation runs with exactly `t` parties, so keep one store per distinct reconstruction threshold.
        let mut triple_stores = HashMap::new();
        for t in triple::distinct_thresholds(keyshares.values().map(|d| d.reconstruction_threshold))
        {
            triple_stores.insert(
                t,
                Arc::new(TripleStorage::new(
                    clock.clone(),
                    db.clone(),
                    client.clone(),
                    t,
                )?),
            );
        }

        Ok(Self {
            config,
            mpc_config,
            client,
            triple_stores,
            sign_request_store,
            keyshares,
        })
    }

    pub(super) fn keyshare(&self, domain_id: DomainId) -> anyhow::Result<EcdsaKeyshare> {
        ecdsa_common::lookup_keyshare(&self.keyshares, domain_id)
    }

    /// Returns the triple store for `t`, or an error if no store was
    /// configured for that threshold at construction (e.g., a peer initiated a
    /// follower protocol with an unexpected `t`).
    pub(super) fn triple_store_for_t(
        &self,
        reconstruction_threshold: ReconstructionThreshold,
    ) -> anyhow::Result<Arc<TripleStorage>> {
        self.triple_stores
            .get(&reconstruction_threshold)
            .cloned()
            .ok_or_else(|| {
                let mut configured: Vec<u64> =
                    self.triple_stores.keys().map(|t| t.inner()).collect();
                configured.sort();
                anyhow::anyhow!(
                    "No triple store configured for t = {} (configured: {:?})",
                    reconstruction_threshold.inner(),
                    configured,
                )
            })
    }

    pub(super) fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        self.client.new_channel_for_task(task_id, participants)
    }

    pub(super) fn my_participant_id(&self) -> ParticipantId {
        self.client.my_participant_id()
    }
}

/// Discriminants are explicit and part of the wire format: a variant is only ever appended,
/// never reordered or renumbered, so that nodes on different versions keep decoding each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    } = 0,
    KeyResharing {
        key_event: KeyEventId,
    } = 1,
    ManyTriples {
        start: UniqueId,
        count: u32,
    } = 2,
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    } = 3,
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    } = 4,
    /// Presigning and signing in one computation over the leader's triple pair; no
    /// presignature is involved.
    OnlinePresignSignature {
        id: SignatureId,
        paired_triple_id: UniqueId,
    } = 5,
}

impl From<EcdsaTaskId> for MpcTaskId {
    fn from(val: EcdsaTaskId) -> Self {
        MpcTaskId::EcdsaTaskId(val)
    }
}

impl SignatureProvider for EcdsaSignatureProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = Signature;
    type TaskId = EcdsaTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        ECDSA_TASK_MONITORS
            .make_signature_leader
            .instrument(self.make_signature_leader_choosing_flow(id))
            .await
    }

    async fn run_key_generation_client(
        reconstruction_threshold: TSReconstructionThreshold,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_generation_client_internal(
            reconstruction_threshold,
            channel,
        )
        .await
    }

    async fn run_key_resharing_client(
        new_reconstruction_threshold: TSReconstructionThreshold,
        old_reconstruction_threshold: TSReconstructionThreshold,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_resharing_client_internal(
            new_reconstruction_threshold,
            old_reconstruction_threshold,
            my_share,
            public_key,
            old_participants,
            channel,
        )
        .await
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EcdsaTaskId(task) => match task {
                EcdsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                EcdsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                EcdsaTaskId::ManyTriples { start, count } => {
                    ECDSA_TASK_MONITORS
                        .triple_generation_follower
                        .instrument(self.run_triple_generation_follower(channel, start, count))
                        .await?;
                }
                EcdsaTaskId::Presignature {
                    id,
                    domain_id,
                    paired_triple_id,
                } => {
                    ECDSA_TASK_MONITORS
                        .presignature_generation_follower
                        .instrument(self.run_presignature_generation_follower(
                            channel,
                            id,
                            domain_id,
                            paired_triple_id,
                        ))
                        .await?;
                }
                EcdsaTaskId::Signature {
                    id,
                    presignature_id,
                } => {
                    ECDSA_TASK_MONITORS
                        .make_signature_follower
                        .instrument(self.make_signature_follower(channel, id, presignature_id))
                        .await?;
                }
                EcdsaTaskId::OnlinePresignSignature {
                    id,
                    paired_triple_id,
                } => {
                    ECDSA_TASK_MONITORS
                        .make_online_presign_signature_follower
                        .instrument(self.make_online_presign_signature_follower(
                            channel,
                            id,
                            paired_triple_id,
                        ))
                        .await?;
                }
            },

            _ => anyhow::bail!(
                "ecdsa task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }
        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        // One triple generator per distinct `t` this node serves; cait-sith
        // triples are generated with exactly `t` parties, so each store is fed
        // by a generator running at its own threshold.
        let mut generate_triples = Vec::new();
        for (&t, triple_store) in &self.triple_stores {
            let reconstruction_threshold_usize: usize = t.inner().try_into()?;
            let reconstruction_threshold_bound =
                TSReconstructionThreshold::from(reconstruction_threshold_usize);
            generate_triples.push(tracking::spawn(
                &format!("generate triples for t={}", t.inner()),
                Self::run_background_triple_generation(
                    self.client.clone(),
                    self.mpc_config.clone(),
                    self.config.triple.clone().into(),
                    triple_store.clone(),
                    reconstruction_threshold_bound,
                ),
            ));
        }

        // Held outside the join group below: this reporter never completes, so
        // joining it would mask generator failures. Aborted on drop when this returns.
        let _metrics_task = tracking::spawn(
            "report triple metrics",
            Self::run_triple_metrics_reporting(self.triple_stores.values().cloned().collect()),
        );

        let mut generate_presignatures = Vec::new();
        for (domain_id, data) in &self.keyshares {
            let triple_store = self.triple_store_for_t(data.reconstruction_threshold)?;
            generate_presignatures.push(tracking::spawn(
                &format!("generate presignatures for domain {}", domain_id.0),
                Self::run_background_presignature_generation(
                    self.client.clone(),
                    self.config.presignature.clone().into(),
                    triple_store,
                    *domain_id,
                    data.clone(),
                ),
            ));
        }

        for Err(join_error) in futures::future::join_all(generate_triples).await {
            tracing::error!(
                "ecdsa background triple generation task ended unexpectedly: {join_error}"
            );
        }
        for Err(join_error) in futures::future::join_all(generate_presignatures).await {
            tracing::error!("ecdsa background presignature task ended unexpectedly: {join_error}");
        }

        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::EcdsaTaskId;
    use crate::primitives::{ParticipantId, UniqueId};
    use mpc_primitives::domain::DomainId;
    use mpc_primitives::{AttemptId, EpochId, KeyEventId};
    use near_indexer_primitives::CryptoHash;
    use rstest::rstest;

    fn uid() -> UniqueId {
        UniqueId::new(ParticipantId::from_raw(0), 1, 0)
    }

    fn key_event() -> KeyEventId {
        KeyEventId::new(EpochId::new(0), DomainId(0), AttemptId(0))
    }

    #[rstest]
    #[case(EcdsaTaskId::KeyGeneration { key_event: key_event() }, 0)]
    #[case(EcdsaTaskId::KeyResharing { key_event: key_event() }, 1)]
    #[case(EcdsaTaskId::ManyTriples { start: uid(), count: 64 }, 2)]
    #[case(EcdsaTaskId::Presignature { id: uid(), domain_id: DomainId(0), paired_triple_id: uid() }, 3)]
    #[case(EcdsaTaskId::Signature { id: CryptoHash::default(), presignature_id: uid() }, 4)]
    #[case(EcdsaTaskId::OnlinePresignSignature { id: CryptoHash::default(), paired_triple_id: uid() }, 5)]
    fn ecdsa_task_id__should_keep_borsh_discriminants_stable(
        #[case] task_id: EcdsaTaskId,
        #[case] discriminant: u8,
    ) {
        // When
        let encoded = borsh::to_vec(&task_id).unwrap();

        // Then
        assert_eq!(encoded[0], discriminant);
    }
}
