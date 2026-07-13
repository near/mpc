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
use crate::providers::ecdsa_common;
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::SignRequestStorage;
use crate::tracking;
use mpc_node_config::ConfigFile;

use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::MaxMalicious;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::ecdsa::robust_ecdsa::PresignOutput;
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::frost_secp256k1::keys::SigningShare;

pub struct RobustEcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

pub(super) type PerDomainData = ecdsa_common::PerDomainData<PresignOutput>;

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
        let per_domain_data = ecdsa_common::build_per_domain_data(&clock, &db, &client, keyshares)?;

        Ok(Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            per_domain_data,
        })
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        ecdsa_common::lookup_domain_data(&self.per_domain_data, domain_id)
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
        // For robust-ECDSA the reconstruction lower bound equals `t`, so resharing is identical to cait-sith.
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
        let mut task_labels: Vec<String> = Vec::new();
        let generate_presignatures = self
            .per_domain_data
            .iter()
            .map(|(domain_id, data)| {
                task_labels.push(format!("presignature generation (domain {})", domain_id.0));
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    presign::run_background_presignature_generation(
                        self.client.clone(),
                        self.mpc_config.clone(),
                        data.reconstruction_threshold,
                        self.config.presignature.clone().into(),
                        *domain_id,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        // Generators are `-> !`, so `select_all` fails fast on the first (panicking) exit rather than `join_all` masking it behind the siblings' infinite loops.
        if generate_presignatures.is_empty() {
            return Ok(());
        }
        let (Err(join_error), index, _remaining) =
            futures::future::select_all(generate_presignatures).await;
        anyhow::bail!(
            "Damgard et al background {} task ended unexpectedly: {join_error}",
            task_labels[index]
        )
    }
}

/// Derives `(num_signers, max_malicious)` for robust-ECDSA from the domain's
/// reconstruction threshold `t`. Returns an error if `t < 2`,
/// which the contract's threshold validation already rejects.
pub(super) fn compute_thresholds(
    threshold: ReconstructionThreshold,
) -> anyhow::Result<(usize, MaxMalicious)> {
    let t: usize = threshold.inner().try_into()?;
    anyhow::ensure!(
        t >= 2,
        "robust-ECDSA requires a reconstruction threshold of at least 2, got {t}"
    );
    let max_malicious = t
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("robust-ECDSA max_malicious underflow for t={t}"))?;
    let num_signers = t
        .checked_mul(2)
        .and_then(|two_t| two_t.checked_sub(1))
        .ok_or_else(|| anyhow::anyhow!("robust-ECDSA signer count overflow for t={t}"))?;
    Ok((num_signers, MaxMalicious::from(max_malicious)))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::compute_thresholds;
    use mpc_primitives::ReconstructionThreshold;
    use threshold_signatures::MaxMalicious;

    #[test]
    fn compute_thresholds__should_map_t_to_2t_minus_1_signers_and_max_malicious_t_minus_1() {
        // Given a domain reconstruction threshold t = 3
        let t = ReconstructionThreshold::new(3);

        // When
        let (num_signers, max_malicious) = compute_thresholds(t).unwrap();

        // Then num_signers = 2t - 1 = 5 and max_malicious = t - 1 = 2
        assert_eq!(num_signers, 5);
        assert_eq!(max_malicious, MaxMalicious::from(2));
        // and the honest-majority invariant 2 * max_malicious + 1 <= num_signers holds.
        assert!(2 * max_malicious.value() < num_signers);
    }

    #[test]
    fn compute_thresholds__should_hold_invariant_across_valid_thresholds() {
        for t in 2..30u64 {
            let (num_signers, max_malicious) =
                compute_thresholds(ReconstructionThreshold::new(t)).unwrap();
            assert_eq!(num_signers, 2 * (t as usize) - 1);
            assert_eq!(max_malicious, MaxMalicious::from((t as usize) - 1));
            assert!(2 * max_malicious.value() < num_signers);
        }
    }

    #[test]
    fn compute_thresholds__should_err_when_threshold_below_two() {
        // Given: robust-ECDSA requires a reconstruction threshold of at least 2
        for t in 0..2u64 {
            // When / Then
            compute_thresholds(ReconstructionThreshold::new(t)).unwrap_err();
        }
    }
}
