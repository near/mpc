import time
import requests

from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.metrics import IntMetricName, NodeMetrics


def get_metric_value_for_node(cluster: MpcCluster, metric_name: str, node_id: int):
    result = cluster.get_int_metric_value_for_node(metric_name, node_id)
    return result if result is not None else 0


def get_node_metrics_all_nodes(cluster: MpcCluster) -> list[NodeMetrics]:
    number_nodes = len(cluster.mpc_nodes)

    network_metrics = [NodeMetrics(0, 0, 0, 0, 0) for _ in range(number_nodes)]
    for i in range(len(cluster.mpc_nodes)):
        network_metrics[i] = get_network_metrics_for_node(cluster, i)
        print(f"Node {i}: {network_metrics[i]}")
    return network_metrics


def get_network_metrics_for_node(cluster: MpcCluster, node_id: int):
    queue_size = get_queue_size_per_node(cluster, node_id)
    requests_indexed = get_requests_indexed_per_node(cluster, node_id)
    responses_indexed = get_responses_indexed_per_node(cluster, node_id)
    matching_responses_indexed = get_matching_responses_indexed_per_node(
        cluster, node_id
    )

    mpc_cluster_failed_signatures_count = get_metric_value_for_node(
        cluster, IntMetricName.MPC_CLUSTER_FAILED_SIGNATURES_COUNT, node_id
    )
    return NodeMetrics(
        queue_size,
        requests_indexed,
        responses_indexed,
        matching_responses_indexed,
        mpc_cluster_failed_signatures_count,
    )


def get_queue_attemps_generated(cluster: MpcCluster):
    led_requests = cluster.get_int_metric_value(
        IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_ATTEMPTS_GENERATED
    ) + cluster.get_int_metric_value(
        IntMetricName.MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED
    )
    return sum(a for a in led_requests if a is not None)


def get_queue_size_per_node(cluster: MpcCluster, node_id: int):
    return get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_SIZE, node_id
    ) + get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_CKDS_QUEUE_SIZE, node_id
    )


def get_requests_indexed_per_node(cluster: MpcCluster, node_id: int):
    return get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_REQUESTS_INDEXED, node_id
    ) + get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_CKDS_QUEUE_REQUESTS_INDEXED, node_id
    )


def get_responses_indexed_per_node(cluster: MpcCluster, node_id: int):
    return get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_RESPONSES_INDEXED, node_id
    ) + get_metric_value_for_node(
        cluster, IntMetricName.MPC_PENDING_CKDS_QUEUE_RESPONSES_INDEXED, node_id
    )


def get_matching_responses_indexed_per_node(cluster: MpcCluster, node_id: int):
    return get_metric_value_for_node(
        cluster,
        IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_MATCHING_RESPONSES_INDEXED,
        node_id,
    ) + get_metric_value_for_node(
        cluster,
        IntMetricName.MPC_PENDING_CKDS_QUEUE_MATCHING_RESPONSES_INDEXED,
        node_id,
    )


def assert_num_presignatures_available(
    cluster: MpcCluster, expected_num_presignatures_available: int, timeout_seconds: int
):
    """
    Asserts that the number of presignatures available for each node in the cluster is exactly `expected_num_presignatures_available`.
    Does so by comparing the metric value `MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE` with the expected value.
    Panics in case any of the metrics is unreachable or does not match the expected value before timeout is reached.
    """
    started = time.time()
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (available) before timeout."
        )
        try:
            presignature_count: list[int] = cluster.require_int_metric_values(
                IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
            )
            if int(elapsed) % 2:
                print("Available presignatures:", presignature_count)
            if all(
                x == expected_num_presignatures_available for x in presignature_count
            ):
                print(
                    f"time for reaching expected asset count (available): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        except ValueError:
            # this case might happen if the metric is not yet available
            pass
        time.sleep(0.1)


def assert_num_offline_online_presignatures(
    cluster: MpcCluster,
    nodes_idxs_to_verify: list[int],
    expected_num_presignatures_online: int,
    expected_num_presignatures_offline: int,
    timeout_seconds: int,
):
    """
    Asserts that each node with index in `nodes_idxs_to_verify`:
        - owns exactly `expected_num_presignatures_online` with online participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_ONLINE`)
        - owns exactly `expected_num_presignatures_offline` with offline participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT`)

    Fails in case any of the metrics is not reachable or does not match the expected value before `timeout`
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (online | offline) before timeout."
        )

        try:
            cleanup_done = all(
                (
                    node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    == expected_num_presignatures_online
                    and node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    == expected_num_presignatures_offline
                )
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify)
            )
            if elapsed - last_print >= 5:
                last_print = elapsed
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify):
                    node_name = node.print()
                    peers_block_heights = node.get_peers_block_height_metric_value()
                    print(f"node {node_name} peer block heights: {peers_block_heights}")

                    online = node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    offline = node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    print(
                        f"Asset count node {node_name}: (online {online} | offline {offline})"
                    )
            if cleanup_done:
                print(
                    f"time for reaching expected asset count (online | offline): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)


def assert_num_live_connections(
    cluster: MpcCluster,
    node_idxs: list[int],
    expected_num_connected: int,
    timeout_seconds: int,
):
    """
    Asserts that each node in node_idx is connected to exactly `expected_num_connected` peers.
    """
    for node_idx in node_idxs:
        cluster.mpc_nodes[node_idx].assert_num_live_connections(
            expected_num_connected, timeout_seconds
        )


def assert_indexer_lag(
    cluster: MpcCluster,
    faulty_node_idx: int,
    active_node_idxs: list[int],
    min_lag_blocks: int = 10,
    timeout_seconds: int = 120,
):
    """
    This function:
        - asserts that the nodes correctly expose the `metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT` metric
        - returns only after the indexer of the node with `faulty_node_idx` lags at least `min_lag_blocks` behind every active nodes.
    Raises an exception if the timeout is exceeded or if there is no valid metric
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            f"Timed out waiting for node {faulty_node_idx} to lag {min_lag_blocks} behind {active_node_idxs}."
        )
        try:
            block_heights: list[int] = cluster.require_int_metric_values(
                IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
            )
            if elapsed - last_print >= 5:
                print(f"Block heights: {block_heights}")
                last_print = elapsed
            faulty_node_height: int = block_heights[faulty_node_idx]
            node_considered_stalled = all(
                [
                    faulty_node_height + min_lag_blocks
                    <= block_heights[active_node_idx]
                    for active_node_idx in active_node_idxs
                ]
            )
            if node_considered_stalled:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)
