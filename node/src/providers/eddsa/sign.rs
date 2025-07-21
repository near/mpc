use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use crate::providers::eddsa::kdf::derive_keygen_output;
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::sign_request::SignatureId;
use anyhow::Context;
use mpc_contract::primitives::signature::Tweak;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::eddsa::sign::sign;
use threshold_signatures::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::Signature;
use threshold_signatures::frost_ed25519::VerifyingKey;
use threshold_signatures::protocol::Participant;
use tokio::time::timeout;

impl EddsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        self: Arc<Self>,
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
            .new_channel_for_task(EddsaTaskId::Signature { id }, participants)?;

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
        .await?;

        let Some((signature, verifying_key)) = result else {
            anyhow::bail!("eddsa resulting signature doesn't contain value for the leader!");
        };

        Ok((signature, verifying_key))
    }

    pub(super) async fn make_signature_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        id: SignatureId,
    ) -> anyhow::Result<()> {
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;

        let threshold = self.mpc_config.participants.threshold as usize;

        let Some(keygen_output) = self.keyshares.get(&sign_request.domain) else {
            anyhow::bail!("No keyshare for domain {:?}", sign_request.domain);
        };

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
        .await?;

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
        let derived_keygen_output =
            derive_keygen_output(&self.keygen_output, self.tweak.as_bytes());

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
        )?;

        // TODO(#306): metrics
        let signature: Option<Signature> = run_protocol("eddsa sign", channel, protocol).await?;

        Ok(signature.map(|signature| (signature, derived_keygen_output.public_key)))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
