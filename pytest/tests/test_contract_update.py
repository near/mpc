# /usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys v0 mpc contract.
Proposes a contract update (v1).
votes on the contract update.
Verifies that the update was executed.
"""

import sys
import pathlib


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import (
    MIGRATION_CONTRACT_BINARY_PATH,
    UpdateArgsV2,
    load_mpc_contract,
)


def test_update_from_current(compile_migration_contract):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 3, 1, load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 2)
    cluster.send_and_await_signature_requests(1)
    cluster.send_and_await_ckd_requests(1)
    new_contract = UpdateArgsV2(MIGRATION_CONTRACT_BINARY_PATH)
    cluster.propose_update(new_contract.borsh_serialize())
    cluster.vote_update(nodes=cluster.get_voters()[0:2], update_id=0)
    cluster.assert_is_deployed(new_contract.code())
