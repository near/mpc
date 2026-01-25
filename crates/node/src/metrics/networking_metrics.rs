use std::sync::LazyLock;

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};

#[allow(dead_code)]
pub(crate) const INCOMING_CONNECTION: &str = "incoming";
pub(crate) const OUTGOING_CONNECTION: &str = "outgoing";

pub(crate) const PING_MESSAGE: &str = "ping";
pub(crate) const INDEXER_HEIGHT_MESSAGE: &str = "indexer_height";
pub(crate) const MPC_START_MESSAGE: &str = "mpc_start";
pub(crate) const MPC_COMPUTATION_MESSAGE: &str = "mpc_computation";
pub(crate) const MPC_ABORT_MESSAGE: &str = "mpc_abort";
pub(crate) const MPC_SUCCESS_MESSAGE: &str = "mpc_success";

const LABEL_MY_PARTICIPANT_ID: &str = "my_participant_id";
const LABEL_PEER_PARTICIPANT_ID: &str = "peer_participant_id";
const LABEL_CONNECTION_DIRECTION: &str = "connection_direction";
const LABEL_MESSAGE_TYPE: &str = "message_type";

// Conservative Estimate
const MTU_BYTES: f64 = 1280.0;
const NETWORK_MESSAGE_SIZES_BYTES_BUKCETS: &[f64] = &[
    100.0,
    200.0,
    MTU_BYTES / 2.0,
    MTU_BYTES,
    MTU_BYTES * 2.0,
    MTU_BYTES * 4.0,
    MTU_BYTES * 8.0,
    MTU_BYTES * 12.0,
    MTU_BYTES * 16.0,
    MTU_BYTES * 20.0,
];

pub(crate) static NETWORK_LIVE_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "mpc_network_live_connections",
        "Current state of the mesh network connections",
        &[LABEL_MY_PARTICIPANT_ID, LABEL_PEER_PARTICIPANT_ID],
    )
    .unwrap()
});

pub(crate) static MPC_P2P_NETWORK_BYTES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_p2p_network_bytes_total",
        "Number of bytes sent transmitted on this network connection",
        &[
            LABEL_MY_PARTICIPANT_ID,
            LABEL_PEER_PARTICIPANT_ID,
            LABEL_CONNECTION_DIRECTION,
            LABEL_MESSAGE_TYPE,
        ],
    )
    .unwrap()
});

pub(crate) static MPC_P2P_NETWORK_MESSAGE_SIZES_BYTES: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec!(
            "mpc_p2p_network_message_sizes",
            "Number of bytes sent transmitted on this network connection",
            &[
                LABEL_MY_PARTICIPANT_ID,
                LABEL_PEER_PARTICIPANT_ID,
                LABEL_CONNECTION_DIRECTION,
                LABEL_MESSAGE_TYPE,
            ],
            NETWORK_MESSAGE_SIZES_BYTES_BUKCETS.to_vec()
        )
        .unwrap()
    });
