#! /usr/bin/env python3
"""
Deploys mpc contract.
Deploys a test contract with a function that makes parallel sign calls.
Calls the test function and ensures a successful response.
"""

import sys
import base64
import pytest
import pathlib
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, constants
from common_lib.shared import metrics
from common_lib.contracts import load_parallel_sign_contract


# TODO: this test is almost the same as the general parallel signs test. Eventually they should be unified
@pytest.mark.parametrize("num_parallel_requests", [3])
@pytest.mark.no_atexit_cleanup
def test_parallel_sign_calls(
    compile_parallel_contract, num_parallel_requests, shared_cluster: shared.MpcCluster
):
    # start cluster and deploy mpc contract
    contract = load_parallel_sign_contract()

    print("Deploying parallel contract")
    shared_cluster.deploy_secondary_contract(contract)

    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        initial_node_metrics = shared.get_node_metrics_all_nodes(shared_cluster)
        initial_queue_attempts = shared.get_queue_attemps_generated(shared_cluster)
        if sum(node_metric.queue_size for node_metric in initial_node_metrics) == 0:
            break
        time.sleep(1)

    print("Making parallel request calls")
    # call `parallel_sign` and verify that it returns successfully
    res = shared_cluster.make_function_call_on_secondary_contract(
        function_name="make_parallel_sign_calls",
        args={
            "target_contract": shared_cluster.mpc_contract_account(),
            "ecdsa_calls_by_domain": {1: 0},
            "eddsa_calls_by_domain": {1: 0},
            "ckd_calls_by_domain": {1: 0},
            "robust_ecdsa_calls_by_domain": {0: num_parallel_requests},
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

    target_metrics = metrics.NodeMetrics(0, *[num_parallel_requests] * 3, 0)
    # check metrics to make sure signature requests are handled properly.
    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        metrics_good = True
        current_metrics = shared.get_node_metrics_all_nodes(shared_cluster)
        for i in range(len(shared_cluster.mpc_nodes)):
            if current_metrics[i] - initial_node_metrics[i] != target_metrics:
                metrics_good = False
        led_requests = (
            shared.get_queue_attemps_generated(shared_cluster) - initial_queue_attempts
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
