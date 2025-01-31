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
import pytest
from utils import load_binary_file

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts


@pytest.mark.parametrize(
    "initial_contract_path,update_contract_path",
    [(contracts.V0_CONTRACT_PATH, contracts.CURRENT_CONTRACT_PATH),
     (contracts.V1_CONTRACT_PATH, contracts.CURRENT_CONTRACT_PATH),
     (contracts.CURRENT_CONTRACT_PATH, contracts.MIGRATE_CURRENT_CONTRACT_PATH)
     ],
    ids=["v0 to current", "v1 to current", "current to v2_altered"])
def test_contract_update(initial_contract_path, update_contract_path):
    initial_contract = load_binary_file(initial_contract_path)
    update_contract = load_binary_file(update_contract_path)
    cluster = shared.start_cluster_with_mpc(2, 2, 1, initial_contract)
    # assert correct contract is deployed
    cluster.assert_is_deployed(initial_contract)
    cluster.init_contract(threshold=2)
    # do some requests
    cluster.send_and_await_signature_requests(2)
    # propose v1
    cluster.propose_update(update_contract)
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    ## wait for the transaction to be included
    time.sleep(2)
    # assert v1 is now deployed
    cluster.assert_is_deployed(update_contract)
    cluster.send_and_await_signature_requests(2)
