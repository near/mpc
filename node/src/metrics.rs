use lazy_static::lazy_static;

lazy_static! {
    pub static ref MPC_NUM_TRIPLES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_triples_generated",
            "Number of triples generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_TRIPLES_GENERATION_TIME_MS: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_num_triples_generation_time_ms",
            "Time take to generate a batch of triples"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_PRE_SIGNATURE_TIME_MS: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_num_pre_signature_time_ms",
            "Time take to create a pre signature"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_SIGNATURE_TIME_MS: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_num_signature_time_ms",
            "Time take to create a signature"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_TRIPLES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_available",
            "Number of triples generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PRESIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_presignatures_generated",
            "Number of presignatures generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_available",
            "Number of presignatures generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signatures_generated",
            "Number of signatures generated (initiated by either us or someone else)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_indexer_num_receipt_execution_outcomes",
            "Number of receipt execution outcomes processed by the near indexer"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_REQUESTS_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_requests",
            "Number of signatures requests indexed"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_REQUESTS_LEADER: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!(
            "mpc_num_signature_requests_leader",
            "Number of signatures requests for which this node is the leader",
            &["result"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_received",
            "Number of passive signature requests received from mpc peers"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_lookup_succeeded",
            "Number of passive signature requests successfully looked up in local DB"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_SENT: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_sent",
            "Number of signature responses sent by this node. Note that transactions can still be
             rejected later when they arrive at the chunk producer, and we wouldn't know of that."
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_failed_to_send_immediately",
            "Number of signature responses sent by this node, where the sending failed immediately
             at the local node. Note that transactions can still be rejected later when they arrive
             at the chunk producer, and we wouldn't know of that."
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_sign_responses_indexed",
            "Number of signature responses sent by this node subsequently observed on chain",
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_TIMED_OUT: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_sign_responses_timed_out",
            "Number of signature responses sent by this node which did not appear on chain in time",
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_INDEXER_LATEST_BLOCK_HEIGHT: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_indexer_latest_block_height",
            "Latest block height processed by the near indexer"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_ACCESS_KEY_NONCE: prometheus::IntGauge = prometheus::register_int_gauge!(
        "mpc_access_key_nonce",
        "Latest observed nonce among transactions submitted using
             the node's access key for its near account",
    )
    .unwrap();
}

lazy_static! {
    pub static ref MPC_CURRENT_JOB_STATE: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "mpc_current_job_state",
            "Current state of the top-level MPC job",
            &["state"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref SIGN_REQUEST_CHANNEL_FAILED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "sign_request_channel_failed",
            "failed to send on channel in sign_request_channel",
        )
        .unwrap();
}

lazy_static! {
    pub static ref NETWORK_LIVE_CONNECTIONS: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "sign_request_channel_failed",
            "failed to send on channel in sign_request_channel",
            &["source_participant_id", "target_participant_id"],
        )
        .unwrap();
}
