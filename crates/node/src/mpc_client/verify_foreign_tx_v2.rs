use std::sync::{Arc, Mutex};

use mpc_primitives::domain::Protocol;
use near_mpc_contract_interface::call_args as contract_args;
use near_time::Clock;

use super::MpcClient;
use crate::foreign_chain_policy::ForeignChainLeadersRefiner;
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{
    ChainSendTransactionRequest, VerifyForeignTransactionRespondV2ArgsExt,
};
use crate::providers::verify_foreign_tx::node_outcomes::NodeOutcomes;
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::providers::verify_foreign_tx::{RoundsEnd, StopLeading};
use crate::requests::queue::{
    ComputationProgress, GenerationAttempt, PendingRequests, RefineEligibleLeaders,
};
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
    /// completed requests of `update` are the answered ones. The node outcomes of a request
    /// count from the moment it opens until it settles.
    pub(crate) fn notify_verify_foreign_tx_v2_block(
        &self,
        pending: &mut PendingVerifyForeignTxV2s,
        update: RequestsUpdate<VerifyForeignTxRequestV2>,
        timed_out: Vec<VerifyForeignTxId>,
    ) {
        notify_v2_block(
            &self.verify_foreign_tx_v2_requests,
            self.network_client.node_outcomes(),
            pending,
            update,
            &timed_out,
        );
    }

    /// Spawns this node's inspection of each V2 request whose block became final, and the
    /// leaders of the requests this node leads now.
    pub(crate) fn spawn_verify_foreign_tx_v2_attempts(
        self: &Arc<Self>,
        pending: &mut PendingVerifyForeignTxV2s,
        tasks: &mut AutoAbortTaskCollection<()>,
        chain_txn_sender: &(impl TransactionSender + 'static),
    ) {
        for request in self.verify_foreign_tx_v2_requests.take_final_uninspected() {
            let provider = self.verify_foreign_tx_provider.clone();
            tasks.spawn_checked(
                &format!(
                    "inspection of verify_foreign_tx_v2 request {:?}",
                    request.id
                ),
                async move { provider.inspect_and_send_node_outcome(request).await },
            );
        }
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
                let response = stop_leading_on_failure(
                    &attempt.computation_progress,
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

    /// Waits for an outcome the counting rule allows, a verdict t nodes signed or an
    /// inconclusive, and runs the signing rounds for it. Each round counts as a led computation.
    async fn compute_verify_foreign_tx_v2_response(
        &self,
        request: &VerifyForeignTxRequestV2,
    ) -> anyhow::Result<contract_args::VerifyForeignTransactionRespondV2Args> {
        let domain_id = request.domain_id;
        match self.domain_to_protocol.get(&domain_id) {
            Some(Protocol::CaitSith) => {
                let provider = &self.verify_foreign_tx_provider;
                let round = provider.prepare_outcome_round(request.id).await?;
                let signed_outcome = provider.lead_outcome_rounds(round).await?;
                contract_args::VerifyForeignTransactionRespondV2Args::from_signed_outcome(
                    request.yield_id,
                    signed_outcome,
                )
            }
            Some(Protocol::ConfidentialKeyDerivation | Protocol::RobustEcdsa | Protocol::Frost) => {
                anyhow::bail!("Signature scheme is not allowed for domain: {domain_id:?}")
            }
            None => anyhow::bail!("Signature scheme is not found for domain: {domain_id:?}"),
        }
    }
}

/// Runs `lead`, and marks in `progress` that this node stopped leading the request when `lead`
/// ends with [`StopLeading`] or [`RoundsEnd`]. The queue then gives this node no further attempt
/// at the request. Any other error leaves the request to a later attempt.
async fn stop_leading_on_failure<T>(
    progress: &Mutex<ComputationProgress<contract_args::VerifyForeignTransactionRespondV2Args>>,
    lead: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    lead.await.inspect_err(|error| {
        if error.is::<StopLeading>() || error.is::<RoundsEnd>() {
            progress.lock().unwrap().stopped_leading = true;
        }
    })
}

fn notify_v2_block<Refiner: RefineEligibleLeaders<VerifyForeignTxRequestV2>>(
    open_requests: &OpenVerifyForeignTxRequestsV2,
    node_outcomes: &NodeOutcomes,
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
    node_outcomes.index(update.requests.iter().map(|request| request.yield_id));
    node_outcomes.forget(&open_requests.notify_new_block(&answered_or_timed_out));
    // The latency histograms time answers only, so a timed out request leaves the queue once it
    // expires.
    pending.notify_new_block(update);
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
