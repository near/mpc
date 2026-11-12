use super::*;
use crate::config::ParticipantsConfig;
use crate::network::testing::new_test_client;
use crate::primitives::{ChannelId, ParticipantId, UniqueId};
use crate::providers::verify_foreign_tx::attempt_evidence::LedAttempt;
use crate::providers::verify_foreign_tx::node_outcome_statement::AttemptId;
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
    evidence: AttemptEvidence,
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
            evidence: AttemptEvidence::new(),
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
            &self.evidence,
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

fn led_attempt() -> LedAttempt {
    LedAttempt {
        id: AttemptId(ChannelId(UniqueId::new(ME, 1_700_000_000, 1))),
        yield_id: request().yield_id,
        leader: ME,
        participants: vec![ME],
        keys: Arc::new(ParticipantsConfig {
            threshold: 1,
            participants: vec![],
        }),
    }
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
fn notify_v2_block__should_forget_the_evidence_of_a_request_once_its_completion_is_final() {
    // Given
    let mut indexed = IndexedV2::new();
    indexed.index(vec![request()], vec![], &[]);
    indexed.evidence.open(led_attempt());
    indexed.index(vec![], vec![request().id], &[]);
    let kept_while_not_final = indexed.evidence.attempts_kept_for(request().yield_id);

    // When
    indexed.finalize_head();

    // Then
    assert_eq!(kept_while_not_final, 1);
    assert_eq!(indexed.evidence.attempts_kept_for(request().yield_id), 0);
}
