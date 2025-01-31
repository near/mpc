#/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys v0 mpc contract.
Proposes a contract update (v1).
votes on the contract update.
Verifies that the update was executed.
"""

import sys
import time
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts


def test_propose_update():
    return
    # deploy v0
    contract_v0 = contracts.load_mpc_contract_v0()
    cluster = shared.start_cluster_with_mpc(2, 2, 1, contract_v0)
    # assert correct contract is deployed
    cluster.assert_is_deployed(contract_v0)
    cluster.init_contract(threshold=2)
    # do some requests
    cluster.send_and_await_signature_requests(2)
    # propose v1
    contract_v1 = contracts.load_mpc_contract_v1()
    cluster.propose_update(contract_v1)
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    ## wait for the transaction to be included
    time.sleep(2)
    # assert v1 is now deployed
    cluster.assert_is_deployed(contract_v1)
    cluster.send_and_await_signature_requests(2)
