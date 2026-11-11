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
use crate::requests::queue::{ComputationProgress, GenerationAttempt, PendingRequests};
use crate::tracking::AutoAbortTaskCollection;
use crate::types::{RequestsUpdate, VerifyForeignTxRequestV2};

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

    /// Opens the V2 requests of a new block, and closes the ones it completes or expires.
    pub(crate) fn notify_verify_foreign_tx_v2_block(
        &self,
        pending: &mut PendingVerifyForeignTxV2s,
        update: RequestsUpdate<VerifyForeignTxRequestV2>,
    ) {
        self.verify_foreign_tx_v2_requests.notify_new_block(&update);
        pending.notify_new_block(update);
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

    async fn compute_verify_foreign_tx_v2_response(
        &self,
        request: &VerifyForeignTxRequestV2,
    ) -> anyhow::Result<contract_args::VerifyForeignTransactionRespondV2Args> {
        let domain_id = request.request.domain_id;
        match self.domain_to_protocol.get(&domain_id) {
            Some(Protocol::CaitSith) => {
                let signed_outcome = self
                    .verify_foreign_tx_provider
                    .make_verify_foreign_tx_v2_leader(request.id)
                    .await?;
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
/// fails. The queue then gives this node no further attempt at the request.
async fn stop_leading_on_failure<T>(
    progress: &Mutex<ComputationProgress<contract_args::VerifyForeignTransactionRespondV2Args>>,
    lead: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    lead.await
        .inspect_err(|_| progress.lock().unwrap().stopped_leading = true)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_leading_on_failure__should_stop_leading_when_the_lead_fails() {
        // Given
        let progress = Mutex::new(ComputationProgress::default());

        // When
        let led = stop_leading_on_failure(&progress, async {
            anyhow::Result::<()>::Err(anyhow::anyhow!("all V2 attempts failed"))
        })
        .await;

        // Then
        led.unwrap_err();
        assert!(progress.lock().unwrap().stopped_leading);
    }

    #[tokio::test]
    async fn stop_leading_on_failure__should_keep_leading_when_the_lead_succeeds() {
        // Given
        let progress = Mutex::new(ComputationProgress::default());

        // When
        let led = stop_leading_on_failure(&progress, async { anyhow::Ok(()) }).await;

        // Then
        led.unwrap();
        assert!(!progress.lock().unwrap().stopped_leading);
    }
}
