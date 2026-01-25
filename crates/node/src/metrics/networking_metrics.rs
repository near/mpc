use std::sync::LazyLock;

use prometheus::{register_int_gauge_vec, IntGaugeVec};

pub(crate) static NETWORK_LIVE_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "mpc_network_live_connections",
        "Current state of the mesh network connections",
        &["my_participant_id", "peer_participant_id"],
    )
    .unwrap()
});
