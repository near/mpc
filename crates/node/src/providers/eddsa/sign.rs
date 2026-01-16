use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::types::SignatureId;
use anyhow::Context;
use mpc_contract::primitives::signature::Tweak;
use rand::rngs::OsRng;
use std::time::Duration;
use threshold_signatures::eddsa::sign::sign;
use threshold_signatures::eddsa::KeygenOutput;
use threshold_signatures::frost_core::Scalar;
use threshold_signatures::frost_ed25519::VerifyingKey;
use threshold_signatures::frost_ed25519::{Ed25519Sha512, Signature};
use threshold_signatures::participants::Participant;
use tokio::time::timeout;

impl EddsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;

        let threshold = self.mpc_config.participants.threshold as usize;
        let running_participants: Vec<_> = self
            .mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        let participants = self
            .client
            .select_random_active_participants_including_me(threshold, &running_participants)
            .context("Can't choose active participants for a eddsa signature")?;

        let channel = self
            .client
            .new_channel_for_task(EddsaTaskId::Signature { id }, participants.clone())?;

        let Some(keygen_output) = self.keyshares.get(&sign_request.domain).cloned() else {
            anyhow::bail!("No keyshare for domain {:?}", sign_request.domain);
        };

        let result = SignComputation {
            keygen_output,
            threshold,
            message: sign_request
                .payload
                .as_eddsa()
                .ok_or_else(|| {
                    anyhow::anyhow!("Signature request payload is not an Eddsa payload")
                })?
                .to_vec(),
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
            })
        })?;

        let Some((signature, verifying_key)) = result else {
            anyhow::bail!("eddsa resulting signature doesn't contain value for the leader!");
        };

        Ok((signature, verifying_key))
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

        let threshold = self.mpc_config.participants.threshold as usize;

        let Some(keygen_output) = self.keyshares.get(&sign_request.domain) else {
            anyhow::bail!("No keyshare for domain {:?}", sign_request.domain);
        };
        let participants = channel.participants().to_vec();
        let _ = SignComputation {
            keygen_output: keygen_output.clone(),
            threshold,
            message: sign_request
                .payload
                .as_eddsa()
                .ok_or_else(|| {
                    anyhow::anyhow!("Signature request payload is not an Eddsa payload")
                })?
                .to_vec(),
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
            })
        })?;

        Ok(())
    }
}

/// Performs an MPC signature operation.
/// This is the same for the initiator and for passive participants.
/// The tweak allows key derivation
pub struct SignComputation {
    pub keygen_output: KeygenOutput,
    pub threshold: usize,
    pub message: Vec<u8>,
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<(Signature, VerifyingKey)>> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<(Signature, VerifyingKey)>> {
        let tweak = Scalar::<Ed25519Sha512>::from_bytes_mod_order(self.tweak.as_bytes());
        let tweak = threshold_signatures::Tweak::new(tweak);
        let derived_keygen_output = KeygenOutput {
            private_share: tweak.derive_signing_share(&self.keygen_output.private_share),
            public_key: tweak.derive_verifying_key(&self.keygen_output.public_key),
        };

        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let protocol = sign(
            cs_participants.as_slice(),
            self.threshold,
            channel.my_participant_id().into(),
            channel.sender().get_leader().into(),
            derived_keygen_output.clone(),
            self.message,
            OsRng,
        )?;

        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature: Option<Signature> = run_protocol("sign eddsa", channel, protocol).await?;

        Ok(signature.map(|signature| (signature, derived_keygen_output.public_key)))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
