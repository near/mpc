#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys the mpc contract.
Sends ckd requests.
Verifies that the mpc nodes index the ckd request.
Waits for ckd responses. Fails if timeout is reached.
Verifies that ckd responses are correct
"""

import sys
import pathlib
import pytest
import atexit


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, ckd, contracts, contract_state
from common_lib.constants import CKD_DEPOSIT


@pytest.fixture(scope="module")
def signing_cluster():
    """
    Spins up a cluster with three nodes, initializes the contract and adds domains. Returns the cluster in a running state.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2,
        2,
        1,
        contracts.load_mpc_contract(),
    )
    cluster.init_cluster(mpc_nodes, 2)
    cluster.wait_for_state(contract_state.ProtocolState.RUNNING)

    yield cluster

    atexit._run_exitfuncs()


@pytest.mark.no_atexit_cleanup
def test_ckd_request_lifecycle(signing_cluster: shared.MpcCluster):
    domains = signing_cluster.contract_state().get_running_domains()

    bls_domain = None
    for domain in domains:
        if domain.scheme == "Bls12381":
            bls_domain = domain
            break
    assert bls_domain is not None

    keyset = signing_cluster.contract_state().keyset()
    assert keyset is not None
    public_key = keyset.get_key(bls_domain.id).key["Bls12381"]["public_key"]

    app_public_key, app_private_key = ckd.generate_app_public_key()
    ckd_args = ckd.generate_ckd_args(bls_domain, app_public_key)
    tx = signing_cluster.request_node.sign_tx(
        signing_cluster.mpc_contract_account(),
        "request_app_private_key",
        ckd_args,
        deposit=CKD_DEPOSIT,
    )
    account_id = signing_cluster.request_node.account_id()

    tx_hash = signing_cluster.request_node.send_tx(tx)["result"]
    res = signing_cluster.request_node.get_tx(tx_hash)
    ck = ckd.assert_ckd_success(res)
    big_y, big_c = ck["big_y"], ck["big_c"]

    assert ckd.verify_ckd(
        account_id.encode(), public_key, app_private_key, big_y, big_c
    )
