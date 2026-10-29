use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::RobustEcdsaTaskId;
use crate::protocol::NamedProtocol;
use crate::providers::robust_ecdsa::{
    EcdsaMessageHash, KeygenOutput, RobustEcdsaSignatureProvider, compute_thresholds,
};
use crate::types::SignatureId;
use anyhow::Context;
use k256::{Scalar, elliptic_curve::PrimeField};
use near_mpc_contract_interface::types::Tweak;
use rand::rngs::OsRng;
use std::time::Duration;
use threshold_signatures::{
    MaxMalicious,
    ecdsa::robust_ecdsa::{PresignArguments, presign_and_sign},
    ecdsa::{Signature, SignatureOption},
    frost_secp256k1::VerifyingKey,
    participants::Participant,
};
use tokio::time::timeout;

impl RobustEcdsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let keyshare = self.keyshare(sign_request.domain)?;
        let (num_signers, robust_ecdsa_threshold) =
            compute_thresholds(keyshare.reconstruction_threshold)?;
        let running_participants: Vec<_> = self
            .mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        let participants = self
            .client
            .select_random_active_participants_including_me(num_signers, &running_participants)
            .context("Can't choose active participants for a robust-ecdsa signature")?;
        let channel = self
            .client
            .new_channel_for_task(RobustEcdsaTaskId::Signature { id }, participants.clone())?;

        let msg_hash = *sign_request
            .payload
            .as_ecdsa()
            .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?;

        let (signature, public_key) = SignComputation {
            keygen_out: keyshare.keygen_output,
            max_malicious: robust_ecdsa_threshold,
            msg_hash: msg_hash.into(),
            tweak: sign_request.tweak,
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
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let keyshare = self.keyshare(sign_request.domain)?;
        let (_num_signers, robust_ecdsa_threshold) =
            compute_thresholds(keyshare.reconstruction_threshold)?;

        let msg_hash = *sign_request
            .payload
            .as_ecdsa()
            .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?;

        let participants = channel.participants().to_vec();
        SignComputation {
            keygen_out: keyshare.keygen_output,
            max_malicious: robust_ecdsa_threshold,
            msg_hash: msg_hash.into(),
            tweak: sign_request.tweak,
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
/// The tweak allows key derivation
pub struct SignComputation {
    pub keygen_out: KeygenOutput,
    pub max_malicious: MaxMalicious,
    pub msg_hash: EcdsaMessageHash,
    pub tweak: Tweak,
}

impl NamedProtocol for SignComputation {
    const NAME: &'static str = "sign robust-ecdsa";
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
        let msg_hash = Scalar::from_repr(self.msg_hash.to_bytes().into())
            .into_option()
            .context("Couldn't construct k256 point")?;

        let derived_public_key = tweak.derive_verifying_key(&self.keygen_out.public_key);

        let protocol = presign_and_sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            channel.my_participant_id().into(),
            PresignArguments {
                keygen_out: self.keygen_out,
                max_malicious: self.max_malicious,
            },
            tweak,
            msg_hash,
            OsRng,
        )?;
        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = Self::run(channel, protocol).await?;
        Ok((signature, derived_public_key))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
