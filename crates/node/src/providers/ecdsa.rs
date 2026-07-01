pub mod key_generation;
pub mod presign;
mod sign;

use near_mpc_contract_interface::types::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;
pub mod key_resharing;
pub mod triple;

pub use triple::TripleStorage;

use crate::config::{MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId, UniqueId};
use crate::providers::SignatureProvider;
use crate::providers::ecdsa_common;
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
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
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
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

pub(super) type PerDomainData = ecdsa_common::PerDomainData<PresignOutput>;

impl EcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, (KeygenOutput, ReconstructionThreshold)>,
    ) -> anyhow::Result<Self> {
        let per_domain_data = ecdsa_common::build_per_domain_data(&clock, &db, &client, keyshares)?;

        // cait-sith triple generation runs with exactly `t` parties, so we keep
        // one store per distinct per-domain reconstruction threshold — known up
        // front, no on-demand creation. Domains may share a `t` or diverge; the
        // contract validates each domain's threshold independently.
        let mut triple_stores = HashMap::new();
        for data in per_domain_data.values() {
            let t = data.reconstruction_threshold;
            if triple_stores.contains_key(&t) {
                continue;
            }
            triple_stores.insert(
                t,
                Arc::new(TripleStorage::new(
                    clock.clone(),
                    db.clone(),
                    client.my_participant_id(),
                    ecdsa_common::active_participants_query(&client),
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
            per_domain_data,
        })
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        ecdsa_common::lookup_domain_data(&self.per_domain_data, domain_id)
    }

    /// Returns the triple store for `t`, or an error if no store was
    /// configured for that threshold at construction (e.g., a peer initiated a
    /// follower protocol with an unexpected `t`).
    pub(super) fn triple_store_for_t(
        &self,
        threshold: ReconstructionThreshold,
    ) -> anyhow::Result<Arc<TripleStorage>> {
        self.triple_stores.get(&threshold).cloned().ok_or_else(|| {
            let mut configured: Vec<u64> = self.triple_stores.keys().map(|t| t.inner()).collect();
            configured.sort();
            anyhow::anyhow!(
                "No triple store configured for t = {} (configured: {:?})",
                threshold.inner(),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum EcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    },
    KeyResharing {
        key_event: KeyEventId,
    },
    ManyTriples {
        start: UniqueId,
        count: u32,
    },
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    },
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    },
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
            .instrument(self.make_signature_leader(id))
            .await
    }

    async fn run_key_generation_client(
        threshold: TSReconstructionThreshold,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: TSReconstructionThreshold,
        old_threshold: TSReconstructionThreshold,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_resharing_client_internal(
            new_threshold,
            old_threshold,
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
            },

            _ => anyhow::bail!(
                "eddsa task handler: received unexpected task id: {:?}",
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
            let threshold_usize: usize = t.inner().try_into()?;
            let threshold_bound = TSReconstructionThreshold::from(threshold_usize);
            generate_triples.push(tracking::spawn(
                &format!("generate triples for t={}", t.inner()),
                Self::run_background_triple_generation(
                    self.client.clone(),
                    self.mpc_config.clone(),
                    self.config.triple.clone().into(),
                    triple_store.clone(),
                    threshold_bound,
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
        for (domain_id, data) in &self.per_domain_data {
            let t = data.reconstruction_threshold;
            let threshold_usize: usize = t.inner().try_into()?;
            let threshold_bound = TSReconstructionThreshold::from(threshold_usize);
            let triple_store = self.triple_store_for_t(t)?;
            generate_presignatures.push(tracking::spawn(
                &format!("generate presignatures for domain {}", domain_id.0),
                Self::run_background_presignature_generation(
                    self.client.clone(),
                    threshold_bound,
                    self.config.presignature.clone().into(),
                    triple_store,
                    *domain_id,
                    data.presignature_store.clone(),
                    data.keyshare.clone(),
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
