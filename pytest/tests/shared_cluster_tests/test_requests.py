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
import pytest


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared


@pytest.mark.parametrize("num_requests", [10])
def test_request_lifecycle(num_requests, shared_cluster: shared.MpcCluster):
    shared_cluster.send_and_await_signature_requests(num_requests)
    shared_cluster.send_and_await_ckd_requests(num_requests)
