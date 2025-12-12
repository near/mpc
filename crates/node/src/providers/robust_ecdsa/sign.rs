use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::UniqueId;
use crate::protocol::run_protocol;
use crate::providers::robust_ecdsa::{
    EcdsaMessageHash, KeygenOutput, PresignatureStorage, RobustEcdsaSignatureProvider,
    RobustEcdsaTaskId,
};
use crate::types::SignatureId;
use anyhow::Context;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use mpc_contract::primitives::signature::Tweak;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ecdsa::robust_ecdsa::{PresignOutput, RerandomizedPresignOutput};
use threshold_signatures::ecdsa::{RerandomizationArguments, Signature, SignatureOption};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::participants::Participant;
use threshold_signatures::ParticipantList;
use tokio::time::timeout;

impl RobustEcdsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let domain_data = self.domain_data(sign_request.domain)?;
        let (presignature_id, presignature) = domain_data.presignature_store.take_owned().await;
        let participants = presignature.participants.clone();
        let channel = self.client.new_channel_for_task(
            RobustEcdsaTaskId::Signature {
                id,
                presignature_id,
            },
            presignature.participants,
        )?;

        let msg_hash = *sign_request
            .payload
            .as_ecdsa()
            .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?;

        let (signature, public_key) = SignComputation {
            keygen_out: domain_data.keyshare,
            presign_out: presignature.presignature,
            msg_hash: msg_hash.into(),
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await
        .inspect_err(|_| {
            participants.iter().for_each(|id| {
                metrics::PARTICIPANT_TOTAL_TIMES_SEEN_IN_FAILED_SIGNATURE_COMPUTATION_LEADER
                    .with_label_values(&[&id.raw().to_string()])
                    .inc();
            });
        })?;

        Ok((
            signature.context("Leader should obtain a signature")?,
            public_key,
        ))
    }

    pub(super) async fn make_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let domain_data = self.domain_data(sign_request.domain)?;
        let msg_hash = *sign_request
            .payload
            .as_ecdsa()
            .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?;

        let participants = channel.participants().to_vec();
        FollowerSignComputation {
            keygen_out: domain_data.keyshare,
            presignature_store: domain_data.presignature_store.clone(),
            presignature_id,
            msg_hash: msg_hash.into(),
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await
        .inspect_err(|_| {
            participants.iter().for_each(|id| {
                metrics::PARTICIPANT_TOTAL_TIMES_SEEN_IN_FAILED_SIGNATURE_COMPUTATION_FOLLOWER
                    .with_label_values(&[&id.raw().to_string()])
                    .inc();
            });
        })?;

        Ok(())
    }
}

/// Performs an MPC signature operation. This is the same for the initiator
/// and for passive participants.
/// The entropy is used to rerandomize the presignature (inspired by [GS21])
/// The tweak allows key derivation
pub struct SignComputation {
    pub keygen_out: KeygenOutput,
    pub presign_out: PresignOutput,
    pub msg_hash: EcdsaMessageHash,
    pub tweak: Tweak,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(SignatureOption, VerifyingKey)> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<(SignatureOption, VerifyingKey)> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let tweak = Scalar::from_repr(self.tweak.as_bytes().into())
            .into_option()
            .context("Couldn't construct k256 point")?;
        let tweak = threshold_signatures::Tweak::new(tweak);

        let msg_hash = Scalar::from_repr(self.msg_hash.as_bytes().into())
            .into_option()
            .context("Couldn't construct k256 point")?;

        let derived_public_key = tweak
            .derive_verifying_key(&self.keygen_out.public_key)
            .to_element()
            .to_affine();
        let participants = ParticipantList::new(&cs_participants).unwrap();

        let rerand_args = RerandomizationArguments::new(
            self.keygen_out.public_key.to_element().to_affine(),
            tweak,
            self.msg_hash.into(),
            self.presign_out.big_r,
            participants,
            self.entropy,
        );
        let rerandomized_presignature =
            RerandomizedPresignOutput::rerandomize_presign(&self.presign_out, &rerand_args)?;

        let protocol = threshold_signatures::ecdsa::robust_ecdsa::sign::sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            channel.my_participant_id().into(),
            derived_public_key,
            rerandomized_presignature,
            msg_hash,
        )?;
        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = run_protocol("sign", channel, protocol).await?;
        Ok((signature, VerifyingKey::new(derived_public_key.into())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs an MPC signature operation as a follower.
/// The difference is that the follower needs to look up the presignature, which may fail.
pub struct FollowerSignComputation {
    pub keygen_out: KeygenOutput,
    pub presignature_id: UniqueId,
    pub presignature_store: Arc<PresignatureStorage>,
    pub msg_hash: EcdsaMessageHash,
    pub tweak: Tweak,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let presign_out = self
            .presignature_store
            .take_unowned(self.presignature_id)?
            .presignature;
        SignComputation {
            keygen_out: self.keygen_out,
            presign_out,
            msg_hash: self.msg_hash,
            tweak: self.tweak,
            entropy: self.entropy,
        }
        .compute(channel)
        .await?;
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
