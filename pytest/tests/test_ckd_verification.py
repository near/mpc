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


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, ckd
from common_lib.contracts import load_mpc_contract
from common_lib.constants import CKD_DEPOSIT
from common_lib.contract_state import ProtocolState


@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(2, 1)])
def test_ckd_request_lifecycle(num_requests, num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 2, num_respond_access_keys, load_mpc_contract()
    )
    cluster.init_cluster(mpc_nodes, 2, ["Bls12381"])
    cluster.wait_for_state(ProtocolState.RUNNING)

    domain = cluster.contract_state().get_running_domains()[0]
    keyset = cluster.contract_state().keyset()
    assert keyset is not None
    public_key = ckd.b58decode_g2(keyset.get_key(0).key["Bls12381"]["public_key"])

    for _ in range(num_requests):
        app_public_key, app_private_key = ckd.generate_app_public_key()
        ckd_args = ckd.generate_ckd_args(domain, app_public_key)
        tx = cluster.request_node.sign_tx(
            cluster.mpc_contract_account(),
            "request_app_private_key",
            ckd_args,
            deposit=CKD_DEPOSIT,
        )
        account_id = cluster.request_node.account_id()

        tx_hash = cluster.request_node.send_tx(tx)["result"]
        res = cluster.request_node.get_tx(tx_hash)
        ck = ckd.assert_ckd_success(res)
        big_y, big_c = ckd.b58decode_g1(ck["big_y"]), ckd.b58decode_g1(ck["big_c"])

        assert ckd.verify_ckd(
            account_id.encode(), public_key, app_private_key, big_y, big_c
        )
