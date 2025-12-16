from enum import Enum
from dataclasses import dataclass


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
    MPC_PENDING_SIGNATURES_QUEUE_SIZE = "mpc_pending_signatures_queue_size"
    MPC_PENDING_SIGNATURES_QUEUE_REQUESTS_INDEXED = (
        "mpc_pending_signatures_queue_requests_indexed"
    )
    MPC_PENDING_SIGNATURES_QUEUE_RESPONSES_INDEXED = (
        "mpc_pending_signatures_queue_responses_indexed"
    )
    MPC_PENDING_SIGNATURES_QUEUE_MATCHING_RESPONSES_INDEXED = (
        "mpc_pending_signatures_queue_matching_responses_indexed"
    )
    MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED = (
        "mpc_pending_ckds_queue_attempts_generated"
    )
    MPC_PENDING_CKDS_QUEUE_SIZE = "mpc_pending_ckds_queue_size"
    MPC_PENDING_CKDS_QUEUE_REQUESTS_INDEXED = "mpc_pending_ckds_queue_requests_indexed"
    MPC_PENDING_CKDS_QUEUE_RESPONSES_INDEXED = (
        "mpc_pending_ckds_queue_responses_indexed"
    )
    MPC_PENDING_CKDS_QUEUE_MATCHING_RESPONSES_INDEXED = (
        "mpc_pending_ckds_queue_matching_responses_indexed"
    )
    MPC_CLUSTER_FAILED_SIGNATURES_COUNT = "mpc_cluster_failed_signatures_count"


class DictMetricName(str, Enum):
    MPC_PEERS_INDEXER_BLOCK_HEIGHTS = "mpc_peers_indexer_block_heights"
    MPC_NETWORK_LIVE_CONNECTIONS = "mpc_network_live_connections"


@dataclass
class NodeMetrics:
    queue_size: int
    requests_indexed: int
    responses_indexed: int
    matching_responses_indexed: int
    mpc_cluster_failed_signatures_count: int

    def __sub__(self, other):
        if not isinstance(other, NodeMetrics):
            raise NotImplementedError
        res = NodeMetrics(0, 0, 0, 0, 0)
        res.queue_size = self.queue_size - other.queue_size
        res.requests_indexed = self.requests_indexed - other.requests_indexed
        res.responses_indexed = self.responses_indexed - other.responses_indexed
        res.matching_responses_indexed = (
            self.matching_responses_indexed - other.matching_responses_indexed
        )
        res.mpc_cluster_failed_signatures_count = (
            self.mpc_cluster_failed_signatures_count
            - other.mpc_cluster_failed_signatures_count
        )
        return res

    def __repr__(self):
        return f"NodeMetrics(queue_size={self.queue_size}, requests_indexed={self.requests_indexed}, responses_indexed={self.responses_indexed}, matching_responses_indexed={self.matching_responses_indexed}, mpc_cluster_failed_signatures_count={self.mpc_cluster_failed_signatures_count})"
