use super::*;
use crate::network::testing::new_test_client;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, signed_by_its_signer,
};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeStatement, SignedNodeOutcome,
};
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use crate::requests::metrics::VERIFY_FOREIGN_TX_V2S_REQUEST_RESPONSE_LATENCY_BLOCKS;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types as dtos;

const ME: ParticipantId = ParticipantId::from_raw(0);

/// The state a node keeps of the V2 requests it indexes, on a chain whose first block is just below
/// the request.
struct IndexedV2 {
    chain: TestChain,
    open_requests: OpenVerifyForeignTxRequestsV2,
    node_outcomes: NodeOutcomes,
    pending: PendingRequests<
        VerifyForeignTxRequestV2,
        contract_args::VerifyForeignTransactionRespondV2Args,
    >,
}

impl IndexedV2 {
    fn new() -> Self {
        Self {
            chain: TestChain::starting_at(BlockHeight::new(999)),
            open_requests: OpenVerifyForeignTxRequestsV2::default(),
            node_outcomes: {
                let node_outcomes = NodeOutcomes::new();
                node_outcomes.set_outcome_keys(outcome_public_keys(&[ME]));
                node_outcomes
            },
            pending: PendingRequests::new(
                Clock::real(),
                vec![ME],
                ME,
                new_test_client(vec![ME], ME),
            ),
        }
    }

    fn index(
        &mut self,
        requests: Vec<VerifyForeignTxRequestV2>,
        answered: Vec<VerifyForeignTxId>,
        timed_out: &[VerifyForeignTxId],
    ) {
        let update = self.chain.extend(requests, answered);
        notify_v2_block(
            &self.open_requests,
            &self.node_outcomes,
            &mut self.pending,
            update,
            timed_out,
        );
    }

    /// Indexes two more blocks, so the head becomes final.
    fn finalize_head(&mut self) {
        self.index(vec![], vec![], &[]);
        self.index(vec![], vec![], &[]);
    }
}

fn request() -> VerifyForeignTxRequestV2 {
    VerifyForeignTxRequestV2 {
        id: CryptoHash([1; 32]),
        receipt_id: CryptoHash([2; 32]),
        yield_id: dtos::YieldId([3; 32]),
        request_block_height: BlockHeight::new(1000),
        request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(1),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: DomainId(0),
        expected_values_hash: dtos::Hash256([4; 32]),
        entropy: [0; 32],
        timestamp_nanosec: 0,
    }
}

fn own_outcome() -> SignedNodeOutcome {
    signed_by_its_signer(NodeOutcomeStatement {
        yield_id: request().yield_id,
        signer: ME,
        outcome: NodeOutcome::Verdict(NodeVerdict::Verified),
    })
}

#[test]
fn notify_v2_block__should_time_the_latency_of_an_answer() {
    // Given
    let mut indexed = IndexedV2::new();
    indexed.index(vec![request()], vec![], &[]);
    indexed.index(vec![], vec![request().id], &[]);
    indexed.finalize_head();
    let timed_before = VERIFY_FOREIGN_TX_V2S_REQUEST_RESPONSE_LATENCY_BLOCKS.get_sample_count();

    // When
    indexed.pending.get_requests_to_attempt();

    // Then
    let timed_after = VERIFY_FOREIGN_TX_V2S_REQUEST_RESPONSE_LATENCY_BLOCKS.get_sample_count();
    assert_eq!(timed_after, timed_before + 1);
}

#[test]
fn notify_v2_block__should_keep_a_timeout_out_of_the_latency() {
    // Given
    let mut indexed = IndexedV2::new();
    indexed.index(vec![request()], vec![], &[]);
    indexed.index(vec![], vec![], &[request().id]);
    indexed.finalize_head();
    let timed_before = VERIFY_FOREIGN_TX_V2S_REQUEST_RESPONSE_LATENCY_BLOCKS.get_sample_count();

    // When
    indexed.pending.get_requests_to_attempt();

    // Then
    let timed_after = VERIFY_FOREIGN_TX_V2S_REQUEST_RESPONSE_LATENCY_BLOCKS.get_sample_count();
    assert_eq!(timed_after, timed_before);
    assert_eq!(indexed.open_requests.get(request().id), None);
}

#[test]
fn notify_v2_block__should_count_the_outcomes_of_a_request_from_its_block_until_it_settles() {
    // Given
    let mut indexed = IndexedV2::new();
    indexed.node_outcomes.receive(ME, own_outcome()).unwrap();
    let counted_before_the_request = indexed.node_outcomes.outcomes_of(request().yield_id);
    indexed.index(vec![request()], vec![], &[]);
    let counted_once_indexed = indexed.node_outcomes.outcomes_of(request().yield_id);
    indexed.index(vec![], vec![request().id], &[]);
    let counted_while_the_completion_is_not_final =
        indexed.node_outcomes.outcomes_of(request().yield_id);

    // When
    indexed.finalize_head();

    // Then
    assert_eq!(counted_before_the_request.len(), 0);
    assert_eq!(counted_once_indexed.len(), 1);
    assert_eq!(counted_while_the_completion_is_not_final.len(), 1);
    assert_eq!(
        indexed.node_outcomes.outcomes_of(request().yield_id).len(),
        0
    );
}

#[rstest::rstest]
#[case::not_a_backer(anyhow::Error::new(StopLeading::NotABacker(NodeVerdict::Verified)))]
#[case::rounds_exhausted_or_local(anyhow::Error::new(RoundsEnd::Local(anyhow::anyhow!(
    "no signature"
))))]
#[case::request_closed_before_a_retry(anyhow::Error::new(RoundsEnd::Stopped(
    StopLeading::RequestClosed
)))]
#[tokio::test]
async fn stop_leading_on_failure__should_stop_leading_when_this_node_ends_its_rounds(
    #[case] stop: anyhow::Error,
) {
    // Given
    let progress = Mutex::new(ComputationProgress::default());

    // When
    let led = stop_leading_on_failure(&progress, async { anyhow::Result::<()>::Err(stop) }).await;

    // Then
    led.unwrap_err();
    assert!(progress.lock().unwrap().stopped_leading);
}

#[tokio::test]
async fn stop_leading_on_failure__should_leave_the_request_to_a_later_attempt_after_another_error()
{
    // Given
    let progress = Mutex::new(ComputationProgress::default());

    // When
    let led = stop_leading_on_failure(&progress, async {
        anyhow::Result::<()>::Err(anyhow::anyhow!("no keyshare for the domain"))
    })
    .await;

    // Then
    led.unwrap_err();
    assert!(!progress.lock().unwrap().stopped_leading);
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
