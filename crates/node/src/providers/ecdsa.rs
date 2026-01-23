pub mod key_generation;
pub mod presign;
mod sign;

use mpc_contract::primitives::key_state::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;
pub mod key_resharing;
pub mod triple;

pub use triple::TripleStorage;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::SignatureProvider;
use crate::storage::SignRequestStorage;
use crate::tracking;

use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;

pub struct EcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
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

        let triple_store = Arc::new(TripleStorage::new(
            clock.clone(),
            db.clone(),
            client.my_participant_id(),
            active_participants_query.clone(),
        )?);

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
            triple_store,
            sign_request_store,
            per_domain_data,
        })
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        self.per_domain_data
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
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
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: usize,
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
        let generate_triples = tracking::spawn(
            "generate triples",
            Self::run_background_triple_generation(
                self.client.clone(),
                self.mpc_config.clone(),
                self.config.triple.clone().into(),
                self.triple_store.clone(),
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
                        self.mpc_config.participants.threshold as usize,
                        self.config.presignature.clone().into(),
                        self.triple_store.clone(),
                        *domain_id,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        generate_triples.await??;
        for task in generate_presignatures {
            task.await??;
        }

        Ok(())
    }
}
