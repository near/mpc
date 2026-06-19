use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::protocol::run_protocol;
use crate::providers::cheetah::{CheetahSignatureProvider, CheetahTaskId};
use crate::types::SignatureId;
use anyhow::Context;
use near_mpc_contract_interface::types::Tweak;
use rand::rngs::OsRng;
use std::time::Duration;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::frost::cheetah::sign::sign;
use threshold_signatures::frost::cheetah::{CheetahTip5, KeygenOutput, tweak_scalar};
use threshold_signatures::frost_core::{Signature, VerifyingKey};
use threshold_signatures::participants::Participant;
use tokio::time::timeout;

type CheetahSignature = Signature<CheetahTip5>;
type CheetahVerifyingKey = VerifyingKey<CheetahTip5>;

impl CheetahSignatureProvider {
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(CheetahSignature, CheetahVerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;

        let threshold: usize = self.mpc_config.participants.threshold.try_into()?;
        let threshold = ReconstructionThreshold::from(threshold);
        let running_participants: Vec<_> = self
            .mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        let participants = self
            .client
            .select_random_active_participants_including_me(
                threshold.value(),
                &running_participants,
            )
            .context("Can't choose active participants for a cheetah signature")?;

        let channel = self
            .client
            .new_channel_for_task(CheetahTaskId::Signature { id }, participants.clone())?;

        let Some(keygen_output) = self.keyshares.get(&sign_request.domain).cloned() else {
            anyhow::bail!("No keyshare for domain {:?}", sign_request.domain);
        };

        let result = SignComputation {
            keygen_output,
            threshold,
            message: cheetah_message(&sign_request.payload)?,
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
            anyhow::bail!("cheetah resulting signature doesn't contain value for the leader!");
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

        let threshold: usize = self.mpc_config.participants.threshold.try_into()?;
        let threshold = ReconstructionThreshold::from(threshold);

        let Some(keygen_output) = self.keyshares.get(&sign_request.domain) else {
            anyhow::bail!("No keyshare for domain {:?}", sign_request.domain);
        };
        let participants = channel.participants().to_vec();
        let _ = SignComputation {
            keygen_output: keygen_output.clone(),
            threshold,
            message: cheetah_message(&sign_request.payload)?,
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

/// The Cheetah message is the 5-belt Nockchain sig-hash digest (40 LE bytes),
/// carried in the variable-length payload arm (the domain's curve selects the scheme).
fn cheetah_message(payload: &near_mpc_crypto_types::primitives::Payload) -> anyhow::Result<Vec<u8>> {
    Ok(payload
        .as_eddsa()
        .ok_or_else(|| anyhow::anyhow!("Cheetah signature request payload is not a byte payload"))?
        .to_vec())
}

/// Performs an MPC signature operation (identical for initiator and passive
/// participants). The tweak enables chainsig-style key derivation.
pub struct SignComputation {
    pub keygen_output: KeygenOutput,
    pub threshold: ReconstructionThreshold,
    pub message: Vec<u8>,
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<(CheetahSignature, CheetahVerifyingKey)>>
    for SignComputation
{
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<(CheetahSignature, CheetahVerifyingKey)>> {
        let tweak = tweak_scalar(&self.tweak.as_bytes());
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
        let signature: Option<CheetahSignature> =
            run_protocol("sign cheetah", channel, protocol).await?;

        Ok(signature.map(|signature| (signature, derived_keygen_output.public_key)))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
