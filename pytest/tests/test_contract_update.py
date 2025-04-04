#/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys v0 mpc contract.
Proposes a contract update (v1).
votes on the contract update.
Verifies that the update was executed.
"""

import json
import sys
import time
import pathlib
from utils import load_binary_file
import yaml

from common_lib import contracts
from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import COMPILED_CONTRACT_PATH, MIGRATE_CURRENT_CONTRACT_PATH, V1_0_1_CONTRACT_PATH, UpdateArgsV1


def deploy_and_init_v2():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 4, 1, contracts.load_mpc_contract())
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    cluster.contract_state().print()
    cluster.send_and_await_signature_requests(1)

    public_key_extended = cluster.contract_state().keyset().keyset[0].key
    # The public key in the state is encoded as a `PublicKeyExtended` struct.
    # We need to extract the inner field which contains the public key.
    public_key = public_key_extended["Secp256k1"]["near_public_key"]

    return cluster, mpc_nodes, public_key


def get_participants_from_near_config():
    # Get the participant set from the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file,
                                        Loader=shared.SafeLoaderIgnoreUnknown)

    participants_map = {}
    account_to_participant_id = {}
    for i, p in enumerate(participants_config['participants']):
        near_account = p['near_account_id']
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        participants_map[near_account] = {
            "account_id": near_account,
            "cipher_pk": [0] * 32,
            "sign_pk": my_pk,
            "url": f"http://{my_addr}:{my_port}",
        }
        account_to_participant_id[near_account] = i

    return {
        "next_id": 2,
        "participants": participants_map,
        "account_to_participant_id": account_to_participant_id,
    }


def test_contract_update():
    update_args = UpdateArgsV1(COMPILED_CONTRACT_PATH)
    cluster, mpc_nodes, public_key = deploy_and_init_v2()
    # migrate v2 to a dummy contract
    dummy_update_args = UpdateArgsV1(code_path=MIGRATE_CURRENT_CONTRACT_PATH)
    cluster.propose_update(dummy_update_args.borsh_serialize())
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    time.sleep(2)
    cluster.assert_is_deployed(dummy_update_args.code())
    # ensure sign transactions are rejected:
    try:
        cluster.send_and_await_signature_requests(1)
    except:
        print("Succesfully migrated from V2 to a different contract code.")
    else:
        assert False
    # kill the nodes, change their config and bring them back up.
    cluster.kill_all()
    cluster.contract_node = cluster.secondary_contract_node
    for node in cluster.mpc_nodes:
        node.change_contract_id(cluster.secondary_contract_node.account_id())
    cluster.run_all()

    # deploy legacy contract
    initial_contract = load_binary_file(V1_0_1_CONTRACT_PATH)
    cluster.deploy_contract(initial_contract)
    cluster.assert_is_deployed(initial_contract)

    # Initialize the legacy contract
    participants = get_participants_from_near_config()
    init_running_args = {
        'epoch': 0,
        'participants': participants,
        'threshold': 2,
        'public_key': public_key,
        'init_config': None,
    }

    # vote for updating the contract to V2
    tx = cluster.contract_node.sign_tx(
        cluster.mpc_contract_account(), 'init_running',
        json.dumps(init_running_args).encode('utf-8'), 1, 150 * TGAS)
    cluster.contract_node.send_txn_and_check_success(tx, 20)
    tx = cluster.contract_node.sign_tx(cluster.mpc_contract_account(),
                                       'version',
                                       json.dumps({}).encode('utf-8'), 1,
                                       150 * TGAS)
    cluster.contract_node.send_txn_and_check_success(tx, 20)

    cluster.define_candidate_set(mpc_nodes[:2])
    cluster.update_participant_status(assert_contract=False)
    cluster.propose_update(update_args.borsh_serialize())
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    time.sleep(2)
    cluster.assert_is_deployed(update_args.code())
    cluster.contract_state().print()
    cluster.send_and_await_signature_requests(1)


# todo: comprehensive test with entire cluster & node + config updates
