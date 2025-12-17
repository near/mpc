import sys
import pathlib
import pytest


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib import shared


@pytest.mark.parametrize("num_requests", [3])
@pytest.mark.no_atexit_cleanup
def test_request_lifecycle(num_requests, shared_cluster: shared.MpcCluster):
    shared_cluster.send_and_await_signature_requests(num_requests)
    shared_cluster.send_and_await_ckd_requests(num_requests)
