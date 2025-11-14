from enum import Enum


class FloatMetricName(str, Enum):
    MPC_NEAR_RESPONDER_BALANCE = "mpc_near_responder_balance"
    MPC_NEAR_SIGNER_BALANCE = "mpc_near_signer_balance"


class IntMetricName(str, Enum):
    MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE = "mpc_owned_num_presignatures_available"
    MPC_OWNED_NUM_PRESIGNATURES_ONLINE = "mpc_owned_num_presignatures_online"
    MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT = (
        "mpc_owned_num_presignatures_with_offline_participant"
    )
    MPC_INDEXER_LATEST_BLOCK_HEIGHT = "mpc_indexer_latest_block_height"
    MPC_PENDING_SIGNATURES_QUEUE_ATTEMPTS_GENERATED = (
        "mpc_pending_signatures_queue_attempts_generated"
    )
    MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED = (
        "mpc_pending_ckds_queue_attempts_generated"
    )


class DictMetricName(str, Enum):
    MPC_PEERS_INDEXER_BLOCK_HEIGHTS = "mpc_peers_indexer_block_heights"
    MPC_NETWORK_LIVE_CONNECTIONS = "mpc_network_live_connections"
