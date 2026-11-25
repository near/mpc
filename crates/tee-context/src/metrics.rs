use std::sync::LazyLock;

pub static MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_attestation_expiry_timestamp_seconds",
            "NEAR block time at which the attestation stored on chain for this node's TLS key \
             expires. -1 if the stored attestation carries no expiry; 0 if none is stored. \
             Subtract mpc_indexer_latest_block_timestamp_seconds, not wall clock, for the \
             remaining time"
        )
        .unwrap()
    });

pub static MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_attestation_last_landed_timestamp_seconds",
            "NEAR block time at which the contract last accepted an attestation for this node's \
             TLS key"
        )
        .unwrap()
    });

pub static MPC_OWN_IMAGE_HASH_ALLOWED: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_own_image_hash_allowed",
        "Whether the Docker image hash this node is running is in the contract's \
             allowlist (1) or not (0)"
    )
    .unwrap()
});

pub static MPC_OWN_IMAGE_HASH_IS_MOST_RECENT: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_own_image_hash_is_most_recent",
            "Whether the Docker image hash this node is running is the most recent \
             hash in the contract's allowlist (1) or not (0)"
        )
        .unwrap()
    });

pub static MPC_OWN_IMAGE_HASH_EXPIRY_TIMESTAMP_SECONDS: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_own_image_hash_expiry_timestamp_seconds",
            "Unix time at which the Docker image hash this node is running is evicted \
             from the contract's allowlist. -1 when the hash never expires (newest \
             entry) or the contract does not report expiry; 0 when the hash is already \
             evicted. Compare against mpc_indexer_latest_block_timestamp_seconds for \
             the remaining time"
        )
        .unwrap()
    });

pub static MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL: LazyLock<prometheus::IntCounterVec> =
    LazyLock::new(|| {
        prometheus::register_int_counter_vec!(
            "mpc_tee_attestation_attempts_total",
            "Total number of completed TEE attestation generation attempts",
            &["outcome"],
        )
        .unwrap()
    });

pub static MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL: LazyLock<prometheus::IntCounterVec> =
    LazyLock::new(|| {
        prometheus::register_int_counter_vec!(
            "mpc_tee_attestation_submissions_total",
            "Total number of TEE attestation submissions to the MPC contract",
            &["outcome"],
        )
        .unwrap()
    });

pub const MPC_TEE_ATTESTATION_OUTCOME_SUCCESS: &str = "success";
pub const MPC_TEE_ATTESTATION_OUTCOME_FAILURE: &str = "failure";
pub const MPC_TEE_ATTESTATION_OUTCOME_SENT: &str = "sent";

pub static MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL: LazyLock<prometheus::IntCounterVec> =
    LazyLock::new(|| {
        prometheus::register_int_counter_vec!(
            "mpc_tee_attestation_round_timeouts_total",
            "Total number of TEE attestation submission rounds that timed out, by stage",
            &["stage"],
        )
        .unwrap()
    });

pub const MPC_TEE_ATTESTATION_STAGE_GENERATE_ATTESTATION: &str = "generate_attestation";
pub const MPC_TEE_ATTESTATION_STAGE_SUBMIT_ATTESTATION: &str = "submit_attestation";

/// An alert cannot fire on a series that does not exist yet.
pub fn init_attestation_freshness_metrics() {
    LazyLock::force(&MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS);
    LazyLock::force(&MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS);
}
