use super::*;
use crate::config::{ParticipantInfo, PersistentSecrets};
use crate::types::RequestsUpdate;
use chain_gateway::event_subscriber::recent_blocks_tracker::RecentBlocksTracker;
use chain_gateway::event_subscriber::recent_blocks_tracker::test_utils::TestBlockMaker;
use ed25519_dalek::SigningKey;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;

mod follower;
mod leader;

const THRESHOLD: usize = 3;
const MOCK_BLOCK_HASH: [u8; 32] = [0xaa; 32];
const REQUEST_HEIGHT: BlockHeight = BlockHeight::new(1000);

const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);
const NOT_FOUND: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Negative(
    ForeignTxVerificationNegativeVerdict::TransactionNotFound,
));

fn tls_key(participant: ParticipantId) -> SigningKey {
    let mut seed = [7; 32];
    seed[..4].copy_from_slice(&participant.raw().to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn signing_key(participant: ParticipantId) -> NodeOutcomeSigningKey {
    NodeOutcomeSigningKey::from(&PersistentSecrets {
        p2p_private_key: tls_key(participant),
        near_signer_key: SigningKey::from_bytes(&[0xff; 32]),
    })
}

fn keys(participants: &[ParticipantId]) -> Arc<ParticipantsConfig> {
    let participants = participants
        .iter()
        .map(|id| ParticipantInfo {
            id: *id,
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: tls_key(*id).verifying_key(),
            near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
        })
        .collect();
    Arc::new(ParticipantsConfig {
        threshold: u64::try_from(THRESHOLD).unwrap(),
        participants,
    })
}

fn ethereum_request() -> dtos::ForeignChainRpcRequest {
    dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
        tx_id: dtos::EvmTxId([0xbb; 32]),
        extractors: [dtos::EvmExtractor::BlockHash].into(),
        finality: dtos::EvmFinality::Finalized,
    })
}

fn request() -> VerifyForeignTxRequestV2 {
    VerifyForeignTxRequestV2 {
        id: CryptoHash([1; 32]),
        receipt_id: CryptoHash([2; 32]),
        yield_id: dtos::YieldId([3; 32]),
        request_block_height: REQUEST_HEIGHT,
        request: dtos::VerifyForeignTransactionRequestV2 {
            request: ethereum_request(),
            domain_id: DomainId(0),
            expected_values: vec![dtos::ExtractedValue::EvmExtractedValue(
                dtos::EvmExtractedValue::BlockHash(dtos::Hash256(MOCK_BLOCK_HASH)),
            )],
        },
        entropy: [0; 32],
        timestamp_nanosec: 0,
    }
}

fn open_requests_with(request: VerifyForeignTxRequestV2) -> Arc<OpenVerifyForeignTxRequestsV2> {
    let open_requests = Arc::new(OpenVerifyForeignTxRequestsV2::default());
    let mut tracker = RecentBlocksTracker::new(crate::requests::queue::REQUEST_EXPIRATION_BLOCKS);
    let block = TestBlockMaker::new().block(u64::from(REQUEST_HEIGHT));
    open_requests.notify_new_block(&RequestsUpdate {
        requests: vec![request],
        completed_requests: vec![],
        block_height: REQUEST_HEIGHT,
        block_status: tracker.add_block(&block.to_block_view()).block_status,
    });
    open_requests
}

fn statement(
    channel: &NetworkTaskChannel,
    signer: ParticipantId,
    outcome: NodeOutcome,
) -> NodeOutcomeStatement {
    NodeOutcomeStatement {
        yield_id: request().yield_id,
        leader: channel.leader(),
        attempt: AttemptId(channel.channel_id()),
        signer,
        outcome,
    }
}
