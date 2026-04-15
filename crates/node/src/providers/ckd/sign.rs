use std::time::Duration;

use anyhow::Context;
use rand::rngs::OsRng;
use tokio::time::timeout;

use near_mpc_contract_interface::types as dtos;
use threshold_signatures::{
    confidential_key_derivation::{
        ckd_pv, protocol::ckd, AppId, ElementG1, ElementG2, KeygenOutput, PublicVerificationKey,
        VerifyingKey,
    },
    participants::Participant,
    ReconstructionLowerBound,
};

use crate::metrics;
use crate::{
    network::{computation::MpcLeaderCentricComputation, NetworkTaskChannel},
    protocol::run_protocol,
    providers::ckd::{CKDProvider, CKDTaskId},
    types::CKDId,
};

impl CKDProvider {
    pub(super) async fn make_ckd_leader(
        &self,
        id: CKDId,
    ) -> anyhow::Result<((ElementG1, ElementG1), VerifyingKey)> {
        let ckd_request = self.ckd_request_store.get(id).await?;

        let threshold: usize = self.mpc_config.participants.threshold.try_into()?;
        let threshold = ReconstructionLowerBound::from(threshold);
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
            .context("Could not choose active participants for a ckd")?;

        let channel = self
            .client
            .new_channel_for_task(CKDTaskId::Ckd { id }, participants)?;

        let Some(keygen_output) = self.keyshares.get(&ckd_request.domain_id.into()).cloned() else {
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
        &self,
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

        let Some(keygen_output) = self.keyshares.get(&ckd_request.domain_id.into()) else {
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
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
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

        let app_id = AppId::try_new(self.app_id.as_ref())?;
        let leader = channel.sender().get_leader().into();
        let my_id = channel.my_participant_id().into();

        let _timer = metrics::MPC_CKD_TIME_ELAPSED.start_timer();
        let result = match self.app_public_key {
            dtos::CKDAppPublicKey::AppPublicKey(pk) => {
                let protocol = ckd(
                    cs_participants.as_slice(),
                    leader,
                    my_id,
                    self.keygen_output,
                    app_id,
                    ElementG1::try_from(&pk)?,
                    OsRng,
                )?;
                run_protocol("ckd", channel, protocol).await?
            }
            dtos::CKDAppPublicKey::AppPublicKeyPV(pv) => {
                let pk1 = ElementG1::try_from(&pv.pk1)?;
                let pk2 = ElementG2::try_from(&pv.pk2)?;
                let protocol = ckd_pv(
                    cs_participants.as_slice(),
                    leader,
                    my_id,
                    self.keygen_output,
                    app_id,
                    PublicVerificationKey::new(pk1, pk2),
                    OsRng,
                )?;
                run_protocol("ckd_pv", channel, protocol).await?
            }
        };

        Ok(result.map(|f| (f.big_y(), f.big_c())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
