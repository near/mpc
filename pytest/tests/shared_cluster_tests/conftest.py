import pytest
import sys
import pathlib
import atexit

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from common_lib import shared, contracts, contract_state


@pytest.fixture(scope="package")
def shared_cluster():
    """
    Spins up a cluster with three nodes per test, initializes the contract and adds
    domains. Returns the cluster in a running state.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2,
        1,
        contracts.load_mpc_contract(),
    )
    cluster.init_cluster(mpc_nodes, 2)
    cluster.wait_for_state(contract_state.ProtocolState.RUNNING)

    yield cluster

    cluster.kill_all()

    atexit._run_exitfuncs()
