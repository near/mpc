/// Metric names scraped from the `/metrics` endpoint of mpc-node.
/// Centralised here so it's easy to see which metrics the e2e tests depend on.
pub const OWNED_PRESIGNATURES_AVAILABLE: &str = "mpc_owned_num_presignatures_available";
pub const OWNED_PRESIGNATURES_ONLINE: &str = "mpc_owned_num_presignatures_online";
pub const OWNED_PRESIGNATURES_OFFLINE: &str =
    "mpc_owned_num_presignatures_with_offline_participant";

pub const SIGNATURES_QUEUE_SIZE: &str = "mpc_pending_signatures_queue_size";
pub const SIGNATURES_QUEUE_REQUESTS_INDEXED: &str = "mpc_pending_signatures_queue_requests_indexed";
pub const SIGNATURES_QUEUE_RESPONSES_INDEXED: &str =
    "mpc_pending_signatures_queue_responses_indexed";
pub const SIGNATURES_QUEUE_MATCHING_RESPONSES: &str =
    "mpc_pending_signatures_queue_matching_responses_indexed";
pub const SIGNATURES_QUEUE_ATTEMPTS: &str = "mpc_pending_signatures_queue_attempts_generated";

pub const CKDS_QUEUE_SIZE: &str = "mpc_pending_ckds_queue_size";
pub const CKDS_QUEUE_REQUESTS_INDEXED: &str = "mpc_pending_ckds_queue_requests_indexed";
pub const CKDS_QUEUE_RESPONSES_INDEXED: &str = "mpc_pending_ckds_queue_responses_indexed";
pub const CKDS_QUEUE_MATCHING_RESPONSES: &str = "mpc_pending_ckds_queue_matching_responses_indexed";
pub const CKDS_QUEUE_ATTEMPTS: &str = "mpc_pending_ckds_queue_attempts_generated";

pub const INDEXER_LATEST_BLOCK_HEIGHT: &str = "mpc_indexer_latest_block_height";

pub const TIMEOUTS_INDEXED: &str = "mpc_num_timeouts_indexed";
