#!/usr/bin/env python3

import sys
import pathlib
import pytest

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

    def handle_result(self, res):
        self.res.append(res)
        try:
            shared.assert_txn_success(res)
            self.num_successes += 1
        except:
            self.num_failures += 1

    def finalize(self):
        print(
            f"Found: {self.num_failures}/{self.expected_failures} and {self.num_successes}/{self.num_requests - self.expected_failures}"
        )
        assert self.num_failures == self.expected_failures, f"expected {self.expected_failures} failures, found {self.num_failures}"
        assert self.num_failures + self.num_successes == self.num_requests, f"expected {self.num_requests} requests, found {self.num_failures + self.num_successes}"


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
