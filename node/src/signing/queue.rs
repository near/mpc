use super::recent_blocks_tracker::RecentBlocksTracker;
use crate::sign_request::SignatureRequest;
use near_indexer_primitives::CryptoHash;
use std::collections::VecDeque;

pub struct PendingSignatureRequests {
    requests: VecDeque<QueuedSignatureRequest>,
    request_expiration_blocks: u64,
    blocks_tracker: RecentBlocksTracker,
}

struct QueuedSignatureRequest {
    request: SignatureRequest,
    block_received: BlockHashAndHeight,
    last_attempt: near_time::Instant,
}

struct BlockHashAndHeight {
    hash: CryptoHash,
    height: u64,
}

impl PendingSignatureRequests {
    pub fn new(request_expiration_blocks: u64) -> Self {
        Self {
            requests: VecDeque::new(),
            request_expiration_blocks,
            blocks_tracker: RecentBlocksTracker::new(request_expiration_blocks),
        }
    }
}
