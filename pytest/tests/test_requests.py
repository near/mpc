#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys the mpc contract.
Sends signature/ckd requests.
Verifies that the mpc nodes index the signature/ckd request.
Waits for the signature/ckd responses. Fails if timeout is reached.
"""

import sys
import pathlib
import time
import pytest


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.constants import TIMEOUT
from common_lib.shared import metrics


@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(10, 1)])
def test_request_lifecycle(num_requests, num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 2, num_respond_access_keys, load_mpc_contract()
    )
    cluster.init_cluster(mpc_nodes, 2)

    started = time.time()
    while True:
        time.sleep(1.0)
        assert time.time() - started < TIMEOUT, "Waiting for account balances"
        # check that the near balance metric works
        responder_balances = cluster.get_float_metric_value(
            metrics.FloatMetricName.MPC_NEAR_RESPONDER_BALANCE
        )
        print(f"responder_balances: {responder_balances}")
        if not all([rb and rb > 0 for rb in responder_balances]):
            continue
        signer_balances = cluster.get_float_metric_value(
            metrics.FloatMetricName.MPC_NEAR_SIGNER_BALANCE
        )
        print(f"signer_balances: {signer_balances}")
        if not all([sb and sb > 0 for sb in signer_balances]):
            continue
        break
    cluster.send_and_await_signature_requests(num_requests)
    cluster.send_and_await_ckd_requests(num_requests)
