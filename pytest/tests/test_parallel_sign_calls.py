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

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts, constants


def load_parallel_sign_contract() -> bytearray:
    """
    returns test contract for parallel sign
    """
    return load_binary_file(contracts.PARALLEL_CONTRACT_BINARY_PATH)


def get_metric_value(cluster, metric_name: str, node_id: int):
    result = cluster.get_int_metric_value_for_node(metric_name, node_id)
    return result if result is not None else 0


@pytest.mark.parametrize("num_parallel_requests", [6])
def test_parallel_sign_calls(compile_parallel_contract, num_parallel_requests):
    assert num_parallel_requests % 3 == 0, "expected even number"
    # start cluster and deploy mpc contract
    mpc_contract = contracts.load_mpc_contract()
    contract = load_parallel_sign_contract()

    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1, mpc_contract)
    cluster.init_cluster(mpc_nodes, 2)

    print("Deploying parallel contract")
    cluster.deploy_secondary_contract(contract)

    print("Making parallel request calls")
    # call `parallel_sign` and verify that it returns successfully
    # TODO(create issue before merge): enable parallel contract CKD tests
    # res = cluster.make_function_call_on_secondary_contract(
    #     function_name="make_parallel_sign_calls",
    #     args={
    #         "target_contract": cluster.mpc_contract_account(),
    #         "ecdsa_calls_by_domain": {0: int(num_parallel_requests / 3)},
    #         "eddsa_calls_by_domain": {1: int(num_parallel_requests / 3)},
    #         "ckd_calls_by_domain": {2: int(num_parallel_requests / 3)},
    #         "seed": 23,
    #     },
    # )
    res = cluster.make_function_call_on_secondary_contract(
        function_name="make_parallel_sign_calls",
        args={
            "target_contract": cluster.mpc_contract_account(),
            "ecdsa_calls_by_domain": {0: int(num_parallel_requests / 2)},
            "eddsa_calls_by_domain": {1: int(num_parallel_requests / 2)},
            "ckd_calls_by_domain": {2: 0},
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

    # check metrics to make sure signature requests are handled properly.
    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        metrics_good = True
        for i in range(len(cluster.mpc_nodes)):
            queue_size = get_metric_value(
                cluster, "mpc_pending_signatures_queue_size", i
            )
            requests_indexed = get_metric_value(
                cluster, "mpc_pending_signatures_queue_requests_indexed", i
            )
            responses_indexed = get_metric_value(
                cluster, "mpc_pending_signatures_queue_responses_indexed", i
            )
            matching_responses_indexed = get_metric_value(
                cluster, "mpc_pending_signatures_queue_matching_responses_indexed", i
            )

            queue_size += get_metric_value(cluster, "mpc_pending_ckds_queue_size", i)
            requests_indexed += get_metric_value(
                cluster, "mpc_pending_ckds_queue_requests_indexed", i
            )
            responses_indexed += get_metric_value(
                cluster, "mpc_pending_ckds_queue_responses_indexed", i
            )
            matching_responses_indexed += get_metric_value(
                cluster, "mpc_pending_ckds_queue_matching_responses_indexed", i
            )
            print(
                f"Node {i}: queue_size={queue_size}, requests_indexed={requests_indexed}, responses_indexed={responses_indexed}, matching_responses_indexed={matching_responses_indexed}"
            )
            if not (
                queue_size == 0
                and requests_indexed == num_parallel_requests
                and responses_indexed == num_parallel_requests
                and matching_responses_indexed == num_parallel_requests
            ):
                metrics_good = False
        led_requests = cluster.get_int_metric_value(
            "mpc_pending_signatures_queue_attempts_generated"
        ) + cluster.get_int_metric_value("mpc_pending_ckds_queue_attempts_generated")
        print(f"led_signatures={led_requests}")
        if sum(led_requests) != num_parallel_requests:
            metrics_good = False
        if metrics_good:
            break
        time.sleep(1)
    print(
        "All requests and responses indexed, all requests had exactly one leader, and signature/ckd queue is empty on all nodes. All Done."
    )
