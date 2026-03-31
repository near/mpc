import sys
import pathlib
import pytest


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib import shared

# TODO(#2663): re-enable when Protocol::DamgardEtAl is wired into the contract
pytestmark = pytest.mark.skip(
    reason="V2Secp256k1 curve removed; robust ECDSA will use Protocol::DamgardEtAl"
)


@pytest.mark.parametrize("num_requests", [3])
@pytest.mark.no_atexit_cleanup
def test_request_lifecycle(num_requests, shared_cluster: shared.MpcCluster):
    shared_cluster.send_and_await_signature_requests(num_requests)
