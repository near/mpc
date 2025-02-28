use lazy_static::lazy_static;

lazy_static! {
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_SIZE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_pending_signatures_queue_size",
            "Number of pending signature requests in the queue"
        )
        .unwrap();
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_BLOCKS_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_pending_signatures_queue_blocks_indexed",
            "Number of blocks indexed by the pending signatures queue"
        )
        .unwrap();
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_FINALIZED_BLOCKS_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_pending_signatures_queue_finalized_blocks_indexed",
            "Number of finalized blocks indexed by the pending signatures queue"
        )
        .unwrap();
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_REQUESTS_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_pending_signatures_queue_requests_indexed",
            "Number of signature requests indexed by the pending signatures queue"
        )
        .unwrap();
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_RESPONSES_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_pending_signatures_queue_responses_indexed",
            "Number of signature responses indexed by the pending signatures queue"
        )
        .unwrap();
    pub static ref MPC_PENDING_SIGNATURES_QUEUE_MATCHING_RESPONSES_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_pending_signatures_queue_matching_responses_indexed",
            "Number of signature responses that match previously indexed signature requests,
                 indexed by the pending signatures queue"
        )
        .unwrap();
}
