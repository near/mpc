use std::sync::LazyLock;

use prometheus::{register_histogram_vec, register_int_gauge_vec, HistogramVec, IntGaugeVec};

#[allow(dead_code)]
pub(crate) const INCOMING_CONNECTION: &str = "incoming";
pub(crate) const OUTGOING_CONNECTION: &str = "outgoing";

pub(crate) const PING_MESSAGE: &str = "ping";
pub(crate) const INDEXER_HEIGHT_MESSAGE: &str = "indexer_height";
pub(crate) const MPC_START_MESSAGE: &str = "mpc_start";
pub(crate) const MPC_COMPUTATION_MESSAGE: &str = "mpc_computation";
pub(crate) const MPC_ABORT_MESSAGE: &str = "mpc_abort";
pub(crate) const MPC_SUCCESS_MESSAGE: &str = "mpc_success";

// TODO(#1852): remove this label. Don't reuse for new metrics.
const LABEL_MY_PARTICIPANT_ID: &str = "my_participant_id";
const LABEL_PEER_PARTICIPANT_ID: &str = "peer_participant_id";
const LABEL_CONNECTION_DIRECTION: &str = "connection_direction";
const LABEL_MESSAGE_TYPE: &str = "message_type";

// Conservative estimate of maximum transmission unit
// https://en.wikipedia.org/wiki/Maximum_transmission_unit
const MTU_BYTES: f64 = 1280.0;
const NETWORK_MESSAGE_SIZES_BYTES_BUCKETS: &[f64] = &[
    16.0,
    32.0,
    64.0,
    128.0,
    512.0,
    1024.0,
    // approx number of Packet
    MTU_BYTES,
    MTU_BYTES * 2.0,
    MTU_BYTES * 4.0,
    MTU_BYTES * 8.0,
    MTU_BYTES * 16.0,
    MTU_BYTES * 32.0,
    MTU_BYTES * 64.0,
    MTU_BYTES * 128.0,
    MTU_BYTES * 256.0,
    MTU_BYTES * 512.0,
    MTU_BYTES * 1024.0, // ~1.3MB
    MTU_BYTES * 2048.0, // ~2.6MiB
    MTU_BYTES * 4096.0, // ~5.2MB
];

pub(crate) static NETWORK_LIVE_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "mpc_network_live_connections",
        "Current state of the mesh network connections",
        &[LABEL_MY_PARTICIPANT_ID, LABEL_PEER_PARTICIPANT_ID],
    )
    .unwrap()
});

pub(crate) static MPC_P2P_NETWORK_MESSAGE_SIZES_BYTES: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec!(
            "mpc_p2p_message_size_bytes",
            "Number of bytes sent transmitted on this network connection",
            &[
                LABEL_PEER_PARTICIPANT_ID,
                LABEL_CONNECTION_DIRECTION,
                LABEL_MESSAGE_TYPE,
            ],
            NETWORK_MESSAGE_SIZES_BYTES_BUCKETS.to_vec()
        )
        .unwrap()
    });
