use super::*;
use crate::network::testing::{current_protocol_versions, new_test_client_with_versions};
use crate::network::wire_format::Packet;
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, signed_by_its_signer,
};
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;

const ME: ParticipantId = ParticipantId::from_raw(0);
const PEER: ParticipantId = ParticipantId::from_raw(1);

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

#[tokio::test(start_paused = true)]
async fn keep_and_send_while_open__should_send_the_outcome_again_until_the_request_closes() {
    // Given
    let participants = vec![ME, PEER];
    let (network, transport) = new_test_client_with_versions(
        participants.clone(),
        ME,
        current_protocol_versions(&participants),
    );
    network
        .node_outcomes()
        .set_outcome_keys(outcome_public_keys(&[ME]));
    let open_requests = OpenVerifyForeignTxRequestsV2::default();
    let mut chain = TestChain::starting_at(BlockHeight::new(999));
    open_requests.notify_new_block(&chain.extend(vec![request()], vec![]));
    network.node_outcomes().index([request().yield_id]);
    let close_after_two_resends = async {
        tokio::time::sleep(OUTCOME_RESEND_INTERVAL * 2 + Duration::from_millis(1)).await;
        open_requests.notify_new_block(&chain.extend(vec![], vec![request().id]));
    };

    // When
    tokio::join!(
        keep_and_send_while_open(&network, &open_requests, request().id, own_outcome()),
        close_after_two_resends,
    );

    // Then
    let sent: Vec<_> = transport
        .take_packets_sent()
        .into_iter()
        .map(|(recipient, packet)| match packet {
            Packet::NodeOutcome(outcome) => (recipient, outcome),
            other => panic!("unexpected packet {other:?}"),
        })
        .collect();
    assert_eq!(sent, vec![(PEER, own_outcome()); 3]);
    let kept: Vec<_> = network
        .node_outcomes()
        .outcomes_of(request().yield_id)
        .iter()
        .map(|outcome| outcome.signed().clone())
        .collect();
    assert_eq!(kept, vec![own_outcome()]);
}
