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

from common_lib import contracts

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import COMPILED_CONTRACT_PATH, MIGRATE_CURRENT_CONTRACT_PATH, UpdateArgsV2, fetch_mainnet_contract, fetch_testnet_contract, load_mpc_contract


def deploy_and_init_v2(domains=['Secp256k1', 'Ed25519']):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 4, 1, contracts.load_mpc_contract())
    cluster.init_cluster(participants=mpc_nodes[:2],
                         threshold=2,
                         domains=domains)
    cluster.contract_state().print()
    return cluster, mpc_nodes


def test_update_from_current():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 3, 1,
                                                       load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 2)
    cluster.send_and_await_signature_requests(1)
    new_contract = UpdateArgsV2(MIGRATE_CURRENT_CONTRACT_PATH)
    cluster.propose_update(new_contract.borsh_serialize())
    for node in cluster.get_voters()[0:2]:
        cluster.vote_update(node, 0)
    cluster.assert_is_deployed(new_contract.code())


@pytest.mark.parametrize("fetch_contract",
                         [fetch_mainnet_contract, fetch_testnet_contract])
def test_update_to_current(fetch_contract):
    current = fetch_contract()
    cluster, mpc_nodes = shared.start_cluster_with_mpc(4, 4, 1, current)
    cluster.define_candidate_set(mpc_nodes)
    cluster.update_participant_status(assert_contract=False)
    cluster.init_contract(threshold=3)
    cluster.add_domains(signature_schemes=['Secp256k1', 'Ed25519'],
                        ignore_vote_errors=True)
    cluster.send_and_await_signature_requests(1)

    time.sleep(1)
    # introduce some state:
    args = {
        'prospective_epoch_id': 1,
        'proposal': cluster.make_threshold_parameters(3)
    }
    for node in cluster.mpc_nodes[0:2]:
        tx = node.sign_tx(cluster.mpc_contract_account(),
                          'vote_new_parameters', args)
        node.send_txn_and_check_success(tx)
        cluster.contract_state().print()
    new_contract = UpdateArgsV2(COMPILED_CONTRACT_PATH)
    cluster.propose_update(new_contract.borsh_serialize())
    for node in cluster.get_voters()[0:3]:
        cluster.vote_update(node, 0)
    time.sleep(2)
    cluster.assert_is_deployed(new_contract.code())
    cluster.wait_for_state("Running")
    cluster.contract_state().print()
    cluster.send_and_await_signature_requests(1)
