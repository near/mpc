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

#[derive(Clone)]
pub(super) struct PerDomainData {
    pub keyshare: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage>,
}

impl EcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> anyhow::Result<Self> {
        let active_participants_query = {
            let network_client = client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        // The set of distinct `t`s the node needs to serve is fully known at
        // startup. Today every ECDSA domain shares the network-wide threshold;
        // once #3164 lands and each domain may declare its own
        // `reconstruction_threshold`, derive this set from the keyshares'
        // domain configs instead.
        let network_threshold = ReconstructionThreshold::new(mpc_config.participants.threshold);
        let mut triple_stores = HashMap::new();
        triple_stores.insert(
            network_threshold,
            Arc::new(TripleStorage::new(
                clock.clone(),
                db.clone(),
                client.my_participant_id(),
                active_participants_query.clone(),
                network_threshold,
            )?),
        );

        let mut per_domain_data = HashMap::new();
        for (domain_id, keyshare) in keyshares {
            let presignature_store = Arc::new(PresignatureStorage::new(
                clock.clone(),
                db.clone(),
                client.my_participant_id(),
                active_participants_query.clone(),
                domain_id,
            )?);
            per_domain_data.insert(
                domain_id,
                PerDomainData {
                    keyshare,
                    presignature_store,
                },
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

    pub(crate) fn participants_config(&self) -> &ParticipantsConfig {
        &self.mpc_config.participants
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        self.per_domain_data
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
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
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_resharing_client_internal(
            new_threshold,
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
        // TODO(#3164): once each domain may carry its own `ReconstructionThreshold`,
        // spawn one background generator per distinct `t` across CaitSith domains
        // and source `t` from `domain.reconstruction_threshold` rather than the
        // network-wide threshold.
        let threshold = ReconstructionThreshold::new(self.mpc_config.participants.threshold);
        let threshold_usize: usize = threshold.inner().try_into()?;
        let threshold_bound = TSReconstructionThreshold::from(threshold_usize);
        let triple_store = self.triple_store_for_t(threshold)?;

        let generate_triples = tracking::spawn(
            "generate triples",
            Self::run_background_triple_generation(
                self.client.clone(),
                self.mpc_config.clone(),
                self.config.triple.clone().into(),
                triple_store.clone(),
                threshold_bound,
            ),
        );

        let generate_presignatures = self
            .per_domain_data
            .iter()
            .map(|(domain_id, data)| {
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    Self::run_background_presignature_generation(
                        self.client.clone(),
                        threshold_bound,
                        self.config.presignature.clone().into(),
                        triple_store.clone(),
                        *domain_id,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        let Err(join_error) = generate_triples.await;
        tracing::error!("ecdsa background triple generation task ended unexpectedly: {join_error}");
        for Err(join_error) in futures::future::join_all(generate_presignatures).await {
            tracing::error!("ecdsa background presignature task ended unexpectedly: {join_error}");
        }

        Ok(())
    }
}
