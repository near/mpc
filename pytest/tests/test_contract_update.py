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
import pytest
from utils import MetricsTracker, load_binary_file
import yaml

from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import V0_CONTRACT_PATH, COMPILED_CONTRACT_PATH, MIGRATE_CURRENT_CONTRACT_PATH, V1_CONTRACT_PATH, UpdateArgsV0, UpdateArgsV1, ConfigV1


@pytest.mark.parametrize(
    "initial_contract_path,update_args",
    [
        pytest.param(V1_CONTRACT_PATH,
                     UpdateArgsV0(COMPILED_CONTRACT_PATH),
                     id="update v1 to current"),
        #pytest.param(COMPILED_CONTRACT_PATH,
        #             UpdateArgsV1(code_path=MIGRATE_CURRENT_CONTRACT_PATH),
        #             id="update current code"),
        #pytest.param(COMPILED_CONTRACT_PATH,
        #             UpdateArgsV1(code_path=None,
        #                          config=ConfigV1(max_num_requests_to_remove=2,
        #                                          request_timeout_blocks=10)),
        #             id="update current config"),
    ])
def test_contract_update(initial_contract_path, update_args):
    initial_contract = load_binary_file(initial_contract_path)
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1,
                                                       initial_contract)
    # Get the participant set from the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file,
                                        Loader=shared.SafeLoaderIgnoreUnknown)

    participants_map = {}
    account_to_participant_id = {}
    next_id = 0

    for i, p in enumerate(participants_config['participants']):
        near_account = p['near_account_id']
        #assert near_account == f"test{i + num_validators}", \
        #    f"This test only works with account IDs 'testX' where X is the node index; expected 'test{i + num_validators}', got {near_account}"
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        participants_map[near_account] = {
            "account_id":
            near_account,
            "cipher_pk": [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            "sign_pk":
            my_pk,
            "url":
            f"http://{my_addr}:{my_port}",
        }
        account_to_participant_id[near_account] = next_id
        next_id += 1
    participants = {
        "next_id": 2,
        "participants": participants_map,
        "account_to_participant_id": account_to_participant_id,
    }

    # Initialize the mpc contract
    init_running_args = {
        'epoch': 0,
        'participants': participants,
        'threshold': 2,
        'public_key': 'ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae',
        'init_config': None,
    }

    tx = cluster.contract_node.sign_tx(
        cluster.mpc_contract_account(), 'init_running',
        json.dumps(init_running_args).encode('utf-8'), 1, 150 * TGAS)

    res = cluster.contract_node.send_txn_and_check_success(tx, 20)
    assert ('SuccessValue' in res['result']['status'])
    cluster.assert_is_deployed(initial_contract)
    cluster.define_candidate_set(mpc_nodes)
    cluster.update_participant_status(
        assert_contract=False
    )  # do not assert when contract is not initialized
    time.sleep(5)
    cluster.propose_update(update_args.borsh_serialize())
    time.sleep(5)
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    time.sleep(2)
    # assert v1 is now deployed
    #if update_args.code() is not None:
    #    print("ensuring contract code is updated")
    cluster.assert_is_deployed(update_args.code())
    cluster.contract_state().print()
    #else:
    #cluster.init_contract(threshold=threshold)
    #self.add_domains(['Secp256k1'])
    # assert correct contract is deployed
    # todo: legacy cluster
    #cluster.assert_is_deployed(initial_contract)
    ##cluster.init_contract(threshold=2)
    ## do some requests
    ##cluster.send_and_await_signature_requests(2,
    ##                                          add_gas=150 * TGAS,
    ##                                          add_deposit=10)
    ## propose v1
    #cluster.propose_update(update_args.borsh_serialize())
    #cluster.vote_update(0, 0)
    #cluster.vote_update(1, 0)
    ### wait for the transaction to be included
    #time.sleep(2)
    ## assert v1 is now deployed
    #if update_args.code() is not None:
    #    print("ensuring contract code is updated")
    #    cluster.assert_is_deployed(update_args.code())
    #else:
    #    print("ensuring config is updated")
    #    expected_config = update_args.dump_json()
    #    deployed_config = cluster.get_config()
    #    assert deployed_config == expected_config
    #print("update completed")
    #cluster.contract_state().print()
    ## add deposit and gas for contract in MIGRATE_CURRENT_CONTRACT_PATH
    #cluster.send_and_await_signature_requests(2,
    #                                          add_gas=150 * TGAS,
    #                                          add_deposit=10)


# In case a nonce conflict occurs during a vote_update call, rerun the test once.
# todo: migration tests
@pytest.mark.skip
@pytest.mark.parametrize("initial_contract_path,update_args", [
    pytest.param(V1_CONTRACT_PATH,
                 UpdateArgsV0(COMPILED_CONTRACT_PATH),
                 id="update v0 to current"),
])
def test_contract_update_trailing_sigs(initial_contract_path, update_args):
    """
    Tests if signatures submitted to V1 that are a response to requests submitted to V0 are successully handled by the contract.
    """
    num_requests = 100
    initial_contract = load_binary_file(initial_contract_path)
    # todo: legacy cluster
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1,
                                                       initial_contract)
    cluster.set_active_mpc_nodes(mpc_nodes)

    # assert correct contract is deployed
    cluster.assert_is_deployed(initial_contract)
    cluster.init_contract(threshold=2)
    cluster.add_domains(['Secp256k1'])
    # propose and vote on contract update (avoid nonce conflicts)
    time.sleep(2)

    def try_send(func, *args, max_tries=20, sleep_duration=0.1):
        n_tries = 0
        while n_tries < max_tries:
            try:
                func(*args)
            except:
                time.sleep(sleep_duration)
                n_tries += 1
            else:
                break

        if n_tries < max_tries:
            print(f"succeeded after {n_tries+1} tries")
        else:
            assert False, "failed to send"

    try_send(cluster.propose_update, update_args.borsh_serialize())
    time.sleep(2)
    try_send(cluster.vote_update, 0, 0)

    # do some requests
    started = time.time()
    tx_hashes, tx_sent = cluster.generate_and_send_signature_requests(
        num_requests, add_gas=150 * TGAS, add_deposit=10)
    print(f"sent {num_requests} signature requests")
    cluster.observe_signature_requests(num_requests, started, tx_sent)
    try_send(cluster.vote_update, 1, 0)
    time.sleep(2)
    if update_args.code() is not None:
        print("ensuring contract code is updated")
        cluster.assert_is_deployed(update_args.code())
    else:
        print("ensuring config is updated")
        expected_config = update_args.dump_json()
        deployed_config = cluster.get_config()
        assert deployed_config == expected_config
    print("update completed")

    class VerificationHelper:

        def __init__(self):
            self.num_trailing_sigs = 0

        def verify(self, tx_res):
            shared.assert_signature_success(tx_res)
            target = "This function is deprecated and shall only be called to handle signature requests submitted to V0 contract"
            if target in json.dumps(tx_res):
                self.num_trailing_sigs += 1

        def final_verification(self):
            print(f"Found {self.num_trailing_sigs} trailing signatures")
            assert self.num_trailing_sigs > 0, "failed to find trailing signatures"

    results = cluster.await_txs_responses(tx_hashes)
    verif_helper = VerificationHelper()
    shared.verify_txs(results, verif_helper.verify)
    verif_helper.final_verification()
