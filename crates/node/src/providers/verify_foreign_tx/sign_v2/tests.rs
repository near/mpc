use super::*;
use crate::network::testing::{
    TestMeshTransportSender, current_protocol_versions, new_test_client_with_versions,
};
use crate::network::wire_format::Packet;
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, signed_by_its_signer,
};
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;

mod inspection;

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
async fn keep_and_send_until_settled__should_send_the_outcome_while_open_and_pause_while_closed() {
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
    let fork_point = chain.head.clone();
    let complete_on_a_losing_fork_then_settle = async {
        let just_after = |sends: u32| OUTCOME_RESEND_INTERVAL * sends + Duration::from_millis(1);
        tokio::time::sleep(just_after(1)).await;
        open_requests.notify_new_block(&chain.extend(vec![], vec![request().id]));
        tokio::time::sleep(just_after(1)).await;
        let other_fork = fork_point.height() + 2;
        open_requests.notify_new_block(&chain.add(&fork_point, other_fork, vec![], vec![]));
        tokio::time::sleep(just_after(1)).await;
        open_requests.notify_new_block(&chain.extend(vec![], vec![request().id]));
        open_requests.notify_new_block(&chain.extend(vec![], vec![]));
        open_requests.notify_new_block(&chain.extend(vec![], vec![]));
    };

    // When
    tokio::join!(
        keep_and_send_until_settled(&network, &open_requests, request().id, own_outcome()),
        complete_on_a_losing_fork_then_settle,
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
    assert!(!open_requests.tracks(request().id));
    let kept: Vec<_> = network
        .node_outcomes()
        .outcomes_of(request().yield_id)
        .iter()
        .map(|outcome| outcome.signed().clone())
        .collect();
    assert_eq!(kept, vec![own_outcome()]);
}
