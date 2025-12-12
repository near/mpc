import pytest
import sys
import pathlib
import atexit

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from common_lib import shared, contracts, contract_state
from common_lib.constants import TIMEOUT

PRESIGNATURES_TO_BUFFER = 6


@pytest.fixture(scope="package")
def shared_cluster():
    """
    Spins up a cluster with three nodes per test, initializes the contract and adds
    domains. Returns the cluster in a running state.
    """
    # TODO: this does not work when using 7 nodes
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        6,
        1,
        contracts.load_mpc_contract(),
        presignatures_to_buffer=PRESIGNATURES_TO_BUFFER,
        triples_to_buffer=0,
    )
    cluster.init_cluster(mpc_nodes, 5, ["V2Secp256k1"])
    cluster.wait_for_state(contract_state.ProtocolState.RUNNING)

    shared.assert_num_presignatures_available(cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT)

    yield cluster

    cluster.kill_all()

    atexit._run_exitfuncs()
