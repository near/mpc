use std::{sync::Arc, time::Duration};

use anyhow::Context;
use contract_interface::types::Bls12381G1PublicKey;
use near_sdk::AccountId;
use rand::rngs::OsRng;
use threshold_signatures::{
    confidential_key_derivation::{protocol::ckd, ElementG1, KeygenOutput, VerifyingKey},
    participants::Participant,
};
use tokio::time::timeout;

use crate::{metrics, trait_extensions::convert_to_contract_dto::TryIntoNodeType};
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
    ) -> anyhow::Result<((ElementG1, ElementG1), VerifyingKey)> {
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

        let public_key = keygen_output.public_key;
        let participants = channel.participants().to_vec();
        let result = CKDComputation {
            keygen_output,
            app_public_key: ckd_request.app_public_key,
            app_id: ckd_request.app_id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.ckd.timeout_sec),
        )
        .await
        .inspect_err(|_| {
            participants.iter().for_each(|id| {
                metrics::PARTICIPANT_TOTAL_TIMES_SEEN_IN_FAILED_SIGNATURE_COMPUTATION_LEADER
                    .with_label_values(&[&id.raw().to_string()])
                    .inc();
            });
        })?;

        let Some((big_y, big_c)) = result else {
            anyhow::bail!("ckd result doesn't contain value for the leader!");
        };

        Ok(((big_y, big_c), public_key))
    }

    pub(super) async fn make_ckd_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        id: CKDId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_CKD_REQUESTS_RECEIVED.inc();
        let ckd_request = timeout(
            Duration::from_secs(self.config.ckd.timeout_sec),
            self.ckd_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_CKD_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let Some(keygen_output) = self.keyshares.get(&ckd_request.domain_id) else {
            anyhow::bail!("No keyshare for domain {:?}", ckd_request.domain_id);
        };
        let participants = channel.participants().to_vec();
        CKDComputation {
            keygen_output: keygen_output.clone(),
            app_public_key: ckd_request.app_public_key,
            app_id: ckd_request.app_id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.ckd.timeout_sec),
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

/// Performs an MPC ckd operation.
/// This is the same for the initiator and for passive participants.
/// The tweak allows key derivation
pub struct CKDComputation {
    pub keygen_output: KeygenOutput,
    pub app_public_key: Bls12381G1PublicKey,
    pub app_id: AccountId,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<(ElementG1, ElementG1)>> for CKDComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<(ElementG1, ElementG1)>> {
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
            self.app_id.as_bytes(),
            self.app_public_key.try_into_node_type()?,
            OsRng,
        )?;

        let _timer = metrics::MPC_CKD_TIME_ELAPSED.start_timer();
        let result = run_protocol("ckd", channel, protocol).await?;

        Ok(result.map(|f| (f.big_y(), f.big_c())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
