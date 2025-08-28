use std::{sync::Arc, time::Duration};

use anyhow::Context;
use k256::AffinePoint;
use near_sdk::{AccountId, PublicKey};
use threshold_signatures::{
    confidential_key_derivation::protocol::ckd, ecdsa::KeygenOutput, frost_secp256k1::VerifyingKey,
    protocol::Participant,
};
use tokio::time::timeout;

use crate::metrics;
use crate::providers::PublicKeyConversion;
use crate::{
    network::{computation::MpcLeaderCentricComputation, NetworkTaskChannel},
    protocol::run_protocol,
    providers::ckd::{CKDProvider, CKDTaskId},
    types::CKDId,
};

impl CKDProvider {
    pub(super) async fn make_ckd_leader(
        self: Arc<Self>,
        id: CKDId,
    ) -> anyhow::Result<(AffinePoint, AffinePoint)> {
        let ckd_request = self.ckd_request_store.get(id).await?;

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
            .context("Could not choose active participants for a ckd")?;

        let channel = self
            .client
            .new_channel_for_task(CKDTaskId::Ckd { id }, participants)?;

        let Some(keygen_output) = self.keyshares.get(&ckd_request.domain_id).cloned() else {
            anyhow::bail!("No keyshare for domain {:?}", ckd_request.domain_id);
        };

        let result = CKDComputation {
            keygen_output,
            app_public_key: ckd_request.app_public_key,
            app_id: ckd_request.app_id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.ckd.timeout_sec),
        )
        .await?;

        let Some((big_y, big_c)) = result else {
            anyhow::bail!("ckd result doesn't contain value for the leader!");
        };

        Ok((big_y, big_c))
    }

    pub(super) async fn make_ckd_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        id: CKDId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let ckd_request = timeout(
            Duration::from_secs(self.config.ckd.timeout_sec),
            self.ckd_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_CKD_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let Some(keygen_output) = self.keyshares.get(&ckd_request.domain_id) else {
            anyhow::bail!("No keyshare for domain {:?}", ckd_request.domain_id);
        };

        CKDComputation {
            keygen_output: keygen_output.clone(),
            app_public_key: ckd_request.app_public_key,
            app_id: ckd_request.app_id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.ckd.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

/// Performs an MPC ckd operation.
/// This is the same for the initiator and for passive participants.
/// The tweak allows key derivation
pub struct CKDComputation {
    pub keygen_output: KeygenOutput,
    pub app_public_key: PublicKey,
    pub app_id: AccountId,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<(AffinePoint, AffinePoint)>> for CKDComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<(AffinePoint, AffinePoint)>> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let protocol = ckd(
            cs_participants.as_slice(),
            channel.sender().get_leader().into(),
            channel.my_participant_id().into(),
            self.keygen_output.private_share,
            self.app_id.as_bytes().into(),
            VerifyingKey::from_near_sdk_public_key(&self.app_public_key)?,
        )?;

        // TODO: this is unused https://github.com/near/mpc/issues/975
        let _timer = metrics::MPC_CKD_TIME_ELAPSED.start_timer();
        let result = run_protocol("ckd", channel, protocol).await?;

        Ok(result.map(|f| (f.big_y().value().to_affine(), f.big_c().value().to_affine())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
