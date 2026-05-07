pub mod presign;
mod sign;

use near_mpc_contract_interface::types::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;

use crate::config::{MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ROBUST_ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::SignRequestStorage;
use crate::tracking;
use mpc_node_config::ConfigFile;

use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::ReconstructionThreshold;
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::MaxMalicious;
use threshold_signatures::ReconstructionLowerBound;

pub struct RobustEcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

#[derive(Clone)]
pub(super) struct PerDomainData {
    pub keyshare: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage>,
    pub reconstruction_threshold: ReconstructionThreshold,
}

#[derive(
    Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, derive_more::From, derive_more::Into,
)]
pub struct EcdsaMessageHash([u8; 32]);

impl EcdsaMessageHash {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl RobustEcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, (KeygenOutput, ReconstructionThreshold)>,
    ) -> anyhow::Result<Self> {
        let active_participants_query = {
            let network_client = client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let mut per_domain_data = HashMap::new();
        for (domain_id, (keyshare, reconstruction_threshold)) in keyshares {
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
                    reconstruction_threshold,
                },
            );
        }

        Ok(Self {
            config,
            mpc_config,
            client,
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
pub enum RobustEcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    },
    KeyResharing {
        key_event: KeyEventId,
    },
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
    },
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    },
}

impl From<RobustEcdsaTaskId> for MpcTaskId {
    fn from(val: RobustEcdsaTaskId) -> Self {
        MpcTaskId::RobustEcdsaTaskId(val)
    }
}

impl SignatureProvider for RobustEcdsaSignatureProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = Signature;
    type TaskId = RobustEcdsaTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        ROBUST_ECDSA_TASK_MONITORS
            .make_signature_leader
            .instrument(self.make_signature_leader(id))
            .await
    }

    async fn run_key_generation_client(
        threshold: ReconstructionLowerBound,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        // Under the post-#3143 design `MaxMalicious = t - 1`, so the
        // underlying CGGMP keygen lower bound is exactly the per-domain `t`
        // we already received here.
        EcdsaSignatureProvider::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: ReconstructionLowerBound,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        // The caller patched `old_participants.threshold` to the OLD epoch's
        // per-domain reconstruction threshold (see `key_events.rs`), so we
        // pass it through directly.
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
            MpcTaskId::RobustEcdsaTaskId(task) => match task {
                RobustEcdsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                RobustEcdsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                RobustEcdsaTaskId::Presignature { id, domain_id } => {
                    ROBUST_ECDSA_TASK_MONITORS
                        .presignature_generation_follower
                        .instrument(
                            self.run_presignature_generation_follower(channel, id, domain_id),
                        )
                        .await?;
                }
                RobustEcdsaTaskId::Signature {
                    id,
                    presignature_id,
                } => {
                    ROBUST_ECDSA_TASK_MONITORS
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
        let generate_presignatures = self
            .per_domain_data
            .iter()
            .map(|(domain_id, data)| {
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    presign::run_background_presignature_generation(
                        self.client.clone(),
                        self.mpc_config.clone(),
                        self.config.presignature.clone().into(),
                        *domain_id,
                        data.reconstruction_threshold,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        for task in generate_presignatures {
            task.await??;
        }

        Ok(())
    }
}

/// Wraps the contract-side `ReconstructionThreshold` into the
/// `MaxMalicious::try_from(ReconstructionLowerBound)` impl from
/// `threshold-signatures` (`MaxMalicious = t - 1` for DamgardEtAl). The
/// contract enforces `t >= 2` (`validate_domain_threshold`) so the underlying
/// subtraction never underflows here.
pub(super) fn max_malicious_for(
    reconstruction_threshold: ReconstructionThreshold,
) -> anyhow::Result<MaxMalicious> {
    let lb = ReconstructionLowerBound::from(usize::try_from(reconstruction_threshold.inner())?);
    Ok(MaxMalicious::try_from(lb)?)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(2, 1)]
    #[case(3, 2)]
    #[case(4, 3)]
    #[case(15, 14)]
    fn max_malicious_for__should_return_t_minus_one(#[case] t: u64, #[case] expected: usize) {
        let m = max_malicious_for(ReconstructionThreshold::new(t)).unwrap();
        assert_eq!(m, MaxMalicious::from(expected));
    }
}
