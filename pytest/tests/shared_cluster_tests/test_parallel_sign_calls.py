#! /usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract.
Deploys a test contract with a function that makes parallel sign calls.
Calls the test function and ensures a successful response.
"""

import sys
import base64
import pytest
import pathlib
import time
from utils import load_binary_file
from dataclasses import dataclass

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts, constants
from common_lib.shared import metrics


@dataclass
class NodeMetrics:
    queue_size: int
    requests_indexed: int
    responses_indexed: int
    matching_responses_indexed: int

    def __sub__(self, other):
        if isinstance(other, NodeMetrics):
            res = NodeMetrics(0, 0, 0, 0)
            res.queue_size = self.queue_size - other.queue_size
            res.requests_indexed = self.requests_indexed - other.requests_indexed
            res.responses_indexed = self.responses_indexed - other.responses_indexed
            res.matching_responses_indexed = (
                self.matching_responses_indexed - other.matching_responses_indexed
            )
            return res


def load_parallel_sign_contract() -> bytearray:
    """
    Returns test contract for parallel sign
    """
    return load_binary_file(contracts.PARALLEL_CONTRACT_BINARY_PATH)


def get_metric_value_for_node(cluster, metric_name: str, node_id: int):
    result = cluster.get_int_metric_value_for_node(metric_name, node_id)
    return result if result is not None else 0


@pytest.mark.parametrize("num_parallel_requests", [6])
def test_parallel_sign_calls(
    compile_parallel_contract, num_parallel_requests, shared_cluster: shared.MpcCluster
):
    assert num_parallel_requests % 3 == 0, "expected number multiple of 3"
    # start cluster and deploy mpc contract
    contract = load_parallel_sign_contract()

    print("Deploying parallel contract")
    shared_cluster.deploy_secondary_contract(contract)

    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        initial_node_metrics = get_node_metrics_all_nodes(shared_cluster)
        initial_queue_attempts = get_queue_attemps_generated(shared_cluster)
        if sum(node_metric.queue_size for node_metric in initial_node_metrics) == 0:
            break
        time.sleep(1)

    print("Making parallel request calls")
    # call `parallel_sign` and verify that it returns successfully
    res = shared_cluster.make_function_call_on_secondary_contract(
        function_name="make_parallel_sign_calls",
        args={
            "target_contract": shared_cluster.mpc_contract_account(),
            "ecdsa_calls_by_domain": {0: num_parallel_requests // 3},
            "eddsa_calls_by_domain": {1: num_parallel_requests // 3},
            "ckd_calls_by_domain": {2: num_parallel_requests // 3},
            "seed": 23,
        },
    )

    # check the return value
    assert (
        "result" in res
        and "status" in res["result"]
        and "SuccessValue" in res["result"]["status"]
    ), res
    encoded_value = res["result"]["status"]["SuccessValue"]
    decoded_value = base64.b64decode(encoded_value).decode("utf-8")
    assert int(decoded_value) == num_parallel_requests

    target_metrics = NodeMetrics(0, *[num_parallel_requests] * 3)
    # check metrics to make sure signature requests are handled properly.
    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        metrics_good = True
        current_metrics = get_node_metrics_all_nodes(shared_cluster)
        for i in range(len(shared_cluster.mpc_nodes)):
            if current_metrics[i] - initial_node_metrics[i] != target_metrics:
                metrics_good = False
        led_requests = (
            get_queue_attemps_generated(shared_cluster) - initial_queue_attempts
        )

        print(f"led_signatures={led_requests}")
        if led_requests != num_parallel_requests:
            metrics_good = False
        if metrics_good:
            break
        time.sleep(1)
    print(
        "All requests and responses indexed, all requests had exactly one leader, and signature/ckd queue is empty on all nodes. All Done."
    )


def get_node_metrics_all_nodes(cluster: shared.MpcCluster):
    number_nodes = len(cluster.mpc_nodes)

    network_metrics = [NodeMetrics(0, 0, 0, 0) for _ in range(number_nodes)]
    for i in range(len(cluster.mpc_nodes)):
        network_metrics[i].queue_size = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_size", i
        )
        network_metrics[i].requests_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_requests_indexed", i
        )
        network_metrics[i].responses_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_responses_indexed", i
        )
        network_metrics[i].matching_responses_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_matching_responses_indexed", i
        )

        network_metrics[i].queue_size += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_size", i
        )
        network_metrics[i].requests_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_requests_indexed", i
        )
        network_metrics[i].responses_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_responses_indexed", i
        )
        network_metrics[i].matching_responses_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_matching_responses_indexed", i
        )
        print(
            f"Node {i}: queue_size={network_metrics[i].queue_size}, requests_indexed={network_metrics[i].requests_indexed}, responses_indexed={network_metrics[i].responses_indexed}, matching_responses_indexed={network_metrics[i].matching_responses_indexed}"
        )
    return network_metrics


def get_queue_attemps_generated(cluster: shared.MpcCluster):
    led_requests = cluster.get_int_metric_value(
        metrics.IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_ATTEMPTS_GENERATED
    ) + cluster.get_int_metric_value(
        metrics.IntMetricName.MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED
    )
    return sum(a for a in led_requests if a is not None)
