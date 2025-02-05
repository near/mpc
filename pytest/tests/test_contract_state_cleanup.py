#!/usr/bin/env python3

import base64
import json
import sys
import pathlib
import time
import pytest
from utils import MetricsTracker

from common_lib import constants
from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


class HandleTestResult():

    def __init__(self, num_requests, expected_failures):
        self.num_failures = 0
        self.num_successes = 0
        self.expected_failures = expected_failures
        self.num_requests = num_requests
        self.res = []
        self.max_tgas = 0
        self.total_tgas = 0

    def handle_result(self, res):
        tgas_used, _ = shared.extract_tx_costs(res)
        tgas_used = tgas_used / TGAS
        self.total_tgas += tgas_used
        self.max_tgas = max(self.max_tgas, tgas_used)
        self.res.append(res)
        try:
            shared.assert_txn_success(res)
            self.num_successes += 1
        except:
            self.num_failures += 1

    def finalize(self):
        print(f"max gas burnt: {self.max_tgas}")
        print(f"avg gas burnt: {self.total_tgas/len(self.res)}")
        print(
            f"Found: {self.num_failures}/{self.expected_failures} and {self.num_successes}/{self.num_requests - self.expected_failures}"
        )
        assert self.num_failures == self.expected_failures, f"expected {self.expected_failures} failures, found {self.num_failures}"
        assert self.num_failures + self.num_successes == self.num_requests, f"expected {self.num_requests} requests, found {self.num_failures + self.num_successes}"


@pytest.mark.ci_excluded
@pytest.mark.slow
@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(5, 1)])
def test_contract_state_cleanup(num_requests, num_respond_access_keys):
    """
    This test verifies that delayed signatures are correctly removed from the state.
    
    Starts 2 near validators and 2 mpc nodes.
    Deploys the current mpc contract with a very small signature timeout.
    Sends signature requests.
    Verifies that the mpc nodes index the signature request.
    Waits for the signature responses.
    It is expected that all but one signature response fail.

    Note that this test is slow.
    """

    cluster = shared.start_cluster_with_mpc(2, 2, num_respond_access_keys,
                                            load_mpc_contract())
    init_args = {'init_config': {'request_timeout_blocks': 0}}
    cluster.init_contract(threshold=2, additional_init_args=init_args)
    result_handler = HandleTestResult(num_requests=num_requests,
                                      expected_failures=num_requests - 1)
    cluster.send_and_await_signature_requests(
        num_requests=num_requests,
        sig_verification=result_handler.handle_result,
    )
    result_handler.finalize()


def extract_success_val(tx_res):
    return base64.b64decode(
        tx_res["result"]["status"]["SuccessValue"]).decode('utf-8')


@pytest.mark.ci_excluded
@pytest.mark.slow
@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(150, 1)])
def test_remove_timed_out_requests(num_requests, num_respond_access_keys):
    """
    Tests if the remove_timed_out_requests function on the contract works correctly.
    """
    result_handler = HandleTestResult(num_requests=num_requests,
                                      expected_failures=num_requests - 1)
    cluster = shared.start_cluster_with_mpc(2, 2, num_respond_access_keys,
                                            load_mpc_contract())
    init_args = {'init_config': {'request_timeout_blocks': 2}}
    cluster.init_contract(threshold=2, additional_init_args=init_args)

    started = time.time()
    metrics = [MetricsTracker(node.near_node) for node in cluster.mpc_nodes]
    tx_hashes, tx_sent = cluster.generate_and_send_signature_requests(
        num_requests)
    print(f"Sent {num_requests} signature requests")
    cluster.observe_signature_requests(started, metrics, tx_sent)
    time.sleep(2)  # give the node a chance to update nonce
    res = cluster.remove_timed_out_requests()
    gas, _ = shared.extract_tx_costs(res)
    print("gas cost (Tgas)", gas / TGAS)
    assert 100 == int(extract_success_val(res))
    results = cluster.await_txs_responses(tx_hashes)
    shared.verify_txs(results, result_handler.handle_result)
    result_handler.finalize()


@pytest.mark.ci_excluded
@pytest.mark.slow
@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(150, 1)])
def test_gas_limit_sign_call(num_requests, num_respond_access_keys):
    """
    Tests if the gas limit `constants.GAS_FOR_SIGN_CALL` is respected, even when maxing the number of removed signature requests
    """
    result_handler = HandleTestResult(num_requests=num_requests + 1,
                                      expected_failures=num_requests)
    cluster = shared.start_cluster_with_mpc(2, 2, num_respond_access_keys,
                                            load_mpc_contract())
    init_args = {'init_config': {'request_timeout_blocks': 1}}
    cluster.init_contract(threshold=2, additional_init_args=init_args)

    started = time.time()
    metrics = [MetricsTracker(node.near_node) for node in cluster.mpc_nodes]
    tx_hashes, tx_sent = cluster.generate_and_send_signature_requests(
        num_requests)
    print(f"Sent {num_requests} signature requests")
    cluster.observe_signature_requests(started, metrics, tx_sent)
    time.sleep(1)  # give node a chance to update nonce
    target_hash, tx_sent = cluster.generate_and_send_signature_requests(1)
    tx_hashes.extend(target_hash)
    results = cluster.await_txs_responses(tx_hashes)
    shared.verify_txs(results, result_handler.handle_result)
    result_handler.finalize()
    assert result_handler.max_tgas < constants.GAS_FOR_SIGN_CALL, "exceeded expected gas limit"
