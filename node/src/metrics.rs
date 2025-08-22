use std::sync::LazyLock;

pub static MPC_NUM_TRIPLES_GENERATED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_num_triples_generated",
        "Number of triples generated (including both owned and not owned)"
    )
    .unwrap()
});
pub static MPC_TRIPLES_GENERATION_TIME_ELAPSED: LazyLock<prometheus::Histogram> =
    LazyLock::new(|| {
        near_o11y::metrics::try_create_histogram(
            "near_mpc_triples_generation_time_elapsed",
            "Time take to generate a batch of triples",
        )
        .unwrap()
    });
pub static MPC_PRE_SIGNATURE_TIME_ELAPSED: LazyLock<prometheus::Histogram> = LazyLock::new(|| {
    near_o11y::metrics::try_create_histogram(
        "near_mpc_pre_signature_time_elapsed",
        "Time take to generate a pre signature",
    )
    .unwrap()
});
pub static MPC_SIGNATURE_TIME_ELAPSED: LazyLock<prometheus::Histogram> = LazyLock::new(|| {
    near_o11y::metrics::try_create_histogram(
        "near_mpc_signature_time_elapsed",
        "Time take to generate a signature",
    )
    .unwrap()
});
pub static MPC_OWNED_NUM_TRIPLES_AVAILABLE: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_owned_num_triples_available",
        "Number of triples generated that we own, and not yet used"
    )
    .unwrap()
});

pub static MPC_OWNED_NUM_TRIPLES_ONLINE: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_owned_num_triples_online",
        "Number of triples generated that we own, and not yet used,
                for which the participant set is confirmed alive"
    )
    .unwrap()
});

pub static MPC_OWNED_NUM_TRIPLES_WITH_OFFLINE_PARTICIPANT: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_with_offline_participant",
            "Number of triples generated that we own, and not yet used,
                for which some participant is offline",
        )
        .unwrap()
    });

pub static MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_available",
            "Number of presignatures generated that we own, and not yet used"
        )
        .unwrap()
    });
pub static MPC_OWNED_NUM_PRESIGNATURES_ONLINE: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_online",
            "Number of presignatures generated that we own, and not yet used,
                for which the participant set is confirmed alive"
        )
        .unwrap()
    });
pub static MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_with_offline_participant",
            "Number of presignatures generated that we own, and not yet used,
                for which some participant is offline",
        )
        .unwrap()
    });
pub static MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_indexer_num_receipt_execution_outcomes",
            "Number of receipt execution outcomes processed by the near indexer"
        )
        .unwrap()
    });

pub static MPC_NUM_SIGN_REQUESTS_INDEXED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_num_signature_requests_indexed",
        "Number of signatures requests seen by the indexer"
    )
    .unwrap()
});

pub static MPC_NUM_SIGN_RESPONSES_INDEXED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_num_signature_responses_indexed",
        "Number of signatures responses seen by the indexer"
    )
    .unwrap()
});
pub static MPC_NUM_SIGNATURE_COMPUTATIONS_LED: LazyLock<prometheus::IntCounterVec> =
    LazyLock::new(|| {
        prometheus::register_int_counter_vec!(
            "mpc_num_signature_computations_led",
            "Number of signature computations that this node led",
            &["result"],
        )
        .unwrap()
    });
pub static MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_received",
            "Number of passive signature requests received from mpc peers"
        )
        .unwrap()
    });

pub static MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_lookup_succeeded",
            "Number of passive signature requests successfully looked up in local DB"
        )
        .unwrap()
    });

pub static MPC_OUTGOING_TRANSACTION_OUTCOMES: LazyLock<prometheus::IntCounterVec> =
    LazyLock::new(|| {
        prometheus::register_int_counter_vec!(
            "mpc_outgoing_transaction_outcomes",
            "Number of transactions sent by this node, by type and outcome",
            &["type", "outcome"],
        )
        .unwrap()
    });
pub static MPC_INDEXER_LATEST_BLOCK_HEIGHT: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_indexer_latest_block_height",
        "Latest block height processed by the near indexer"
    )
    .unwrap()
});
#[allow(dead_code)]
pub static MPC_ACCESS_KEY_NONCE: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_access_key_nonce",
        "Latest observed nonce among transactions submitted using
             the node's access key for its near account",
    )
    .unwrap()
});
pub static MPC_CURRENT_JOB_STATE: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "mpc_current_job_state",
        "Current state of the top-level MPC job",
        &["state"],
    )
    .unwrap()
});
pub static SIGN_REQUEST_CHANNEL_FAILED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "sign_request_channel_failed",
        "failed to send on channel in sign_request_channel",
    )
    .unwrap()
});

pub static CKD_REQUEST_CHANNEL_FAILED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "ckd_request_channel_failed",
        "failed to send on channel in ckd_request_channel",
    )
    .unwrap()
});

pub static NETWORK_LIVE_CONNECTIONS: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "mpc_network_live_connections",
        "Current state of the mesh network connections",
        &["my_participant_id", "peer_participant_id"],
    )
    .unwrap()
});

pub static VERIFY_TEE_REQUESTS_SENT: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "verify_tee_requests_sent",
        "failed to send on channel in sign_request_channel",
    )
    .unwrap()
});

pub static PEERS_INDEXER_HEIGHTS: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "mpc_peers_indexer_block_heights",
        "Latest known block height of peers",
        &["participant"]
    )
    .unwrap()
});

pub static NEAR_RESPONDER_BALANCE: LazyLock<prometheus::Gauge> = LazyLock::new(|| {
    prometheus::register_gauge!(
        "mpc_near_responder_balance",
        "Balance for the mpc responder account"
    )
    .unwrap()
});

pub static NEAR_SIGNER_BALANCE: LazyLock<prometheus::Gauge> = LazyLock::new(|| {
    prometheus::register_gauge!(
        "mpc_near_signer_balance",
        "Balance for the mpc signer account"
    )
    .unwrap()
});

pub static MPC_BUILD_INFO: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "mpc_node_build_info",
        "Metric whose labels indicate node’s version",
        &["release", "build_time", "commit", "rustc_version"],
    )
    .unwrap()
});

/// Initialize the build info metric with current version information
pub fn init_build_info_metric() {
    // Use compile-time constants from built crate
    let version = crate::built_info::PKG_VERSION;
    let build_time = crate::built_info::BUILT_TIME_UTC;
    let commit = crate::built_info::GIT_COMMIT_HASH_SHORT.unwrap_or("unknown");
    let rustc_version = crate::built_info::RUSTC_VERSION;

    MPC_BUILD_INFO
        .with_label_values(&[version, build_time, commit, rustc_version])
        .set(1);
}
