//! Provider for [`Protocol::RobustEcdsa`]
//! domains.
//!
//! # Do not enable this in production
//!
//! The underlying scheme in
//! [`threshold_signatures::ecdsa::robust_ecdsa`] is an insecure stub that leaks the
//! signing key, kept so this plumbing stays exercised until a real robust scheme
//! replaces it. Read that module's docs before enabling a domain for this protocol
//! anywhere. Everything in this module is scheme-agnostic and is expected to survive
//! that replacement unchanged.

pub mod presign;
mod sign;

use crate::network::wire_format::{MpcTaskId, RobustEcdsaTaskId};
pub use presign::PresignatureStorage;
use std::collections::HashMap;

use crate::assets::metrics::{PRESIGNATURE_GAUGES, report_store};
use crate::config::{MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ROBUST_ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::providers::ecdsa_common;
use crate::providers::{DomainKeyshare, EcdsaSignatureProvider, SignatureProvider};
use crate::storage::SignRequestStorage;
use crate::tracking;
use mpc_node_config::ConfigFile;

use crate::types::SignatureId;
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::PrimeField;
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::{DomainId, Protocol};
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::MaxMalicious;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::robust_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::{KeygenOutput, Secp256K1Sha256, Signature};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::frost_secp256k1::keys::SigningShare;

pub struct RobustEcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    keyshares: HashMap<DomainId, EcdsaKeyshare>,
}

pub(super) type EcdsaKeyshare = ecdsa_common::EcdsaKeyshare<PresignOutput>;

#[derive(
    Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, derive_more::From, derive_more::Into,
)]
pub struct EcdsaMessageHash([u8; 32]);

impl EcdsaMessageHash {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn validate(self) -> anyhow::Result<Self> {
        let scalar = k256::Scalar::from_repr(self.0.into())
            .into_option()
            .context("ECDSA payload cannot be converted to Scalar")?;
        anyhow::ensure!(
            !bool::from(scalar.is_zero()),
            "ECDSA does not support a zero message hash"
        );
        Ok(self)
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
        keyshares: HashMap<DomainId, DomainKeyshare<Secp256K1Sha256>>,
    ) -> anyhow::Result<Self> {
        let keyshares = ecdsa_common::build_keyshares(&clock, &db, client.clone(), keyshares)?;

        Ok(Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            keyshares,
        })
    }

    pub(super) fn keyshare(&self, domain_id: DomainId) -> anyhow::Result<EcdsaKeyshare> {
        ecdsa_common::lookup_keyshare(&self.keyshares, domain_id)
    }

    /// Reports the owned-asset gauges for every presignature store of this
    /// provider, labelled by domain. Robust ECDSA uses no triples.
    pub fn report_asset_metrics(&self) {
        for (domain_id, keyshare) in &self.keyshares {
            report_store(
                &PRESIGNATURE_GAUGES,
                domain_id,
                &keyshare.presignature_store,
            );
        }
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
            .keyshares
            .iter()
            .map(|(domain_id, data)| {
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    presign::run_background_presignature_generation(
                        self.client.clone(),
                        self.mpc_config.clone(),
                        self.config.presignature.clone().into(),
                        *domain_id,
                        data.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        for Err(join_error) in futures::future::join_all(generate_presignatures).await {
            tracing::error!(
                "Robust ECDSA background presignature task ended unexpectedly: {join_error}"
            );
        }

        Ok(())
    }
}

/// Derives `(num_signers, max_malicious)` for robust-ECDSA from the domain's
/// reconstruction threshold `t`, with `num_signers` taken from
/// [`Protocol::required_active_signers`] so node and contract agree on it.
/// Returns an error if `t < 2`, which the contract's threshold validation
/// already rejects.
pub(super) fn compute_thresholds(
    reconstruction_threshold: ReconstructionThreshold,
) -> anyhow::Result<(usize, MaxMalicious)> {
    let t: usize = reconstruction_threshold.inner().try_into()?;
    anyhow::ensure!(
        t >= 2,
        "robust-ECDSA requires a reconstruction threshold of at least 2, got {t}"
    );
    let max_malicious = t
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("robust-ECDSA max_malicious underflow for t={t}"))?;
    let num_signers: usize = Protocol::RobustEcdsa
        .required_active_signers(reconstruction_threshold)
        .try_into()?;
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
