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

/// An alert cannot fire on a series that does not exist yet.
pub fn init_attestation_freshness_metrics() {
    LazyLock::force(&MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS);
    LazyLock::force(&MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS);
}
