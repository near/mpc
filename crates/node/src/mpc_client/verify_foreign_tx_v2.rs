use std::sync::Arc;

use mpc_primitives::domain::Protocol;
use near_mpc_contract_interface::call_args as contract_args;
use near_time::Clock;
use tokio::time::Duration;

use super::{MpcClient, run_led_computation};
use crate::foreign_chain_policy::ForeignChainLeadersRefiner;
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{
    ChainSendTransactionRequest, VerifyForeignTransactionRespondV2ArgsExt,
};
use crate::metrics;
use crate::providers::verify_foreign_tx::attempt_evidence::AttemptEvidence;
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::requests::queue::{GenerationAttempt, PendingRequests, RefineEligibleLeaders};
use crate::tracking::AutoAbortTaskCollection;
use crate::types::{RequestsUpdate, VerifyForeignTxId, VerifyForeignTxRequestV2};

pub(crate) type PendingVerifyForeignTxV2s = PendingRequests<
    VerifyForeignTxRequestV2,
    contract_args::VerifyForeignTransactionRespondV2Args,
    ForeignChainLeadersRefiner,
>;

impl MpcClient {
    pub(crate) fn new_pending_verify_foreign_tx_v2s(&self) -> PendingVerifyForeignTxV2s {
        PendingRequests::new(
            Clock::real(),
            self.network_client.all_participant_ids(),
            self.network_client.my_participant_id(),
            self.network_client.clone(),
        )
        .with_eligible_leaders_refiner(
            self.verify_foreign_tx_provider
                .new_eligible_leaders_refiner(),
        )
    }

    /// Opens the V2 requests of a new block, and closes the ones it answers or times out. The
    /// completed requests of `update` are the answered ones.
    pub(crate) fn notify_verify_foreign_tx_v2_block(
        &self,
        pending: &mut PendingVerifyForeignTxV2s,
        update: RequestsUpdate<VerifyForeignTxRequestV2>,
        timed_out: Vec<VerifyForeignTxId>,
    ) {
        notify_v2_block(
            &self.verify_foreign_tx_v2_requests,
            self.network_client.attempt_evidence(),
            pending,
            update,
            &timed_out,
        );
    }

    pub(crate) fn spawn_verify_foreign_tx_v2_attempts(
        self: &Arc<Self>,
        pending: &mut PendingVerifyForeignTxV2s,
        tasks: &mut AutoAbortTaskCollection<()>,
        chain_txn_sender: &(impl TransactionSender + 'static),
    ) {
        for attempt in pending.get_requests_to_attempt() {
            let this = self.clone();
            let chain_txn_sender = chain_txn_sender.clone();
            tasks.spawn_checked(
                &format!(
                    "leader for verify_foreign_tx_v2 request {:?}",
                    attempt.request.id
                ),
                async move {
                    this.lead_verify_foreign_tx_v2(attempt, chain_txn_sender)
                        .await
                },
            );
        }
    }

    async fn lead_verify_foreign_tx_v2(
        &self,
        attempt: Arc<
            GenerationAttempt<
                VerifyForeignTxRequestV2,
                contract_args::VerifyForeignTransactionRespondV2Args,
            >,
        >,
        chain_txn_sender: impl TransactionSender,
    ) -> anyhow::Result<()> {
        let existing_response = attempt
            .computation_progress
            .lock()
            .unwrap()
            .computed_response
            .clone();
        let response = match existing_response {
            Some(response) => response,
            None => {
                // TODO(#5125): give V2 attempts their own deadline and retries.
                let response = run_led_computation(
                    &metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED,
                    Duration::from_secs(self.config.signature.timeout_sec),
                    self.compute_verify_foreign_tx_v2_response(&attempt.request),
                )
                .await?;
                attempt
                    .computation_progress
                    .lock()
                    .unwrap()
                    .computed_response = Some(response.clone());
                response
            }
        };
        let _ = chain_txn_sender
            .send(ChainSendTransactionRequest::VerifyForeignTransactionRespondV2(response))
            .await;
        attempt
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission = Some(Clock::real().now());
        Ok(())
    }

    async fn compute_verify_foreign_tx_v2_response(
        &self,
        request: &VerifyForeignTxRequestV2,
    ) -> anyhow::Result<contract_args::VerifyForeignTransactionRespondV2Args> {
        let domain_id = request.domain_id;
        match self.domain_to_protocol.get(&domain_id) {
            Some(Protocol::CaitSith) => {
                let signed_verdict = self
                    .verify_foreign_tx_provider
                    .make_verify_foreign_tx_v2_leader(request.id)
                    .await?;
                contract_args::VerifyForeignTransactionRespondV2Args::from_signed_verdict(
                    request.yield_id,
                    signed_verdict,
                )
            }
            Some(Protocol::ConfidentialKeyDerivation | Protocol::RobustEcdsa | Protocol::Frost) => {
                anyhow::bail!("Signature scheme is not allowed for domain: {domain_id:?}")
            }
            None => anyhow::bail!("Signature scheme is not found for domain: {domain_id:?}"),
        }
    }
}

fn notify_v2_block<Refiner: RefineEligibleLeaders<VerifyForeignTxRequestV2>>(
    open_requests: &OpenVerifyForeignTxRequestsV2,
    evidence: &AttemptEvidence,
    pending: &mut PendingRequests<
        VerifyForeignTxRequestV2,
        contract_args::VerifyForeignTransactionRespondV2Args,
        Refiner,
    >,
    update: RequestsUpdate<VerifyForeignTxRequestV2>,
    timed_out: &[VerifyForeignTxId],
) {
    let answered_or_timed_out = RequestsUpdate {
        requests: update.requests.clone(),
        completed_requests: [update.completed_requests.as_slice(), timed_out].concat(),
        block_height: update.block_height,
        block_status: update.block_status.clone(),
    };
    evidence.forget(&open_requests.notify_new_block(&answered_or_timed_out));
    // The latency histograms time answers only, so a timed out request leaves the queue once it
    // expires.
    pending.notify_new_block(update);
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
