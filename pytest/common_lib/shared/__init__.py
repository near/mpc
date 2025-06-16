import json
import os
import pathlib
import subprocess
import sys
from typing import List, Iterable, Optional, Tuple

import base58
import yaml

from common_lib.constants import NEAR_BASE, MPC_BINARY_PATH
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode
from common_lib.shared.near_account import NearAccount
from common_lib.shared.yaml_safeloader import SafeLoaderIgnoreUnknown

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import start_cluster, LocalNode

from transaction import create_create_account_action, create_payment_action, \
    create_full_access_key_action, sign_transaction, serialize_transaction

from key import Key

dot_near = pathlib.Path.home() / '.near'


# Output is deserializable into the rust type near_crypto::SecretKey
def serialize_key(key: Key):
    full_key = bytes(key.decoded_sk())
    return 'ed25519:' + base58.b58encode(full_key).decode('ascii')


def sign_create_account_with_multiple_access_keys_tx(
        creator_key: Key,
        new_account_id,
        keys: List[Key],
        nonce,
        block_hash
) -> bytes:
    create_account_action = create_create_account_action()
    payment_action = create_payment_action(100 * NEAR_BASE)
    access_key_actions = [
        create_full_access_key_action(key.decoded_pk()) for key in keys
    ]
    actions = [create_account_action, payment_action] + access_key_actions
    signed_tx = sign_transaction(
        new_account_id,
        nonce,
        actions,
        block_hash,
        creator_key.account_id,
        creator_key.decoded_pk(),
        creator_key.decoded_sk()
    )
    return serialize_transaction(signed_tx)


def start_neard_cluster_with_cleanup(
        num_validators: int,
        num_mpc_nodes: int,
) -> Tuple[List[LocalNode], List[LocalNode]]:
    rpc_polling_config = {
        "rpc": {
            "polling_config": {
                "polling_timeout": {
                    "secs": 20,
                    "nanos": 0
                },
                "polling_interval": {
                    "secs": 1,
                    "nanos": 0
                },
            }
        }
    }

    client_config_changes = {
        0: rpc_polling_config,
        1: rpc_polling_config
    }

    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 1000], ["block_producer_kickout_threshold", 80]],
        client_config_changes=client_config_changes
    )

    validators = nodes[:num_validators]
    observers = nodes[num_validators:]

    for observer in observers:
        observer.kill(gentle=True)
        observer.reset_data()
        adjust_indexing_shard(observer)

    return validators, observers


def generate_mpc_configs(
        num_mpc_nodes: int,
        num_validators: int,
        presignatures_to_buffer: Optional[int]
):
    participants = ','.join(f'test{i + num_validators}'
                            for i in range(num_mpc_nodes))
    cmd = (
        MPC_BINARY_PATH, 'generate-test-configs',
        '--output-dir', dot_near,
        '--participants', participants,
        '--threshold', str(num_mpc_nodes)
    )
    if presignatures_to_buffer:
        cmd = cmd + (
            '--desired-presignatures-to-buffer', str(presignatures_to_buffer),
        )
    subprocess.run(cmd)


def create_and_dump_responder_config(
        num_respond_aks: int,
        mpc_node: MpcNode,
        cluster: MpcCluster,
):
    if num_respond_aks == 0:
        return
    # FIXME: For whatever reason we can not get `last_block_hash` from non-validator node at this moment
    last_block_hash = cluster.contract_node.last_block_hash()
    account_id = f"respond.{mpc_node.account_id()}"
    access_keys = [
        Key.from_seed_testonly(account_id, seed=f"{s}")
        for s in range(0, num_respond_aks)
    ]
    tx = sign_create_account_with_multiple_access_keys_tx(
        mpc_node.signer_key(),
        account_id,
        access_keys,
        1,
        last_block_hash
    )
    cluster.contract_node.send_txn_and_check_success(tx)
    respond_cfg = {
        'account_id': account_id,
        'access_keys': list(map(serialize_key, access_keys)),
    }
    fname = os.path.join(mpc_node.near_node.node_dir, 'respond.yaml')
    with open(fname, "w") as file:
        yaml.dump(respond_cfg, file, default_flow_style=False)


def adjust_indexing_shard(near_node: LocalNode):
    """Set the node to track shard 0 explicitly in config.json."""
    path = os.path.join(near_node.node_dir, 'config.json')

    with open(path, 'r+') as f:
        config = json.load(f)
        config['tracked_shards'] = [0]
        f.seek(0)
        json.dump(config, f, indent=2)
        f.truncate()

    print(f"Updated near node config: {path}")


class Candidate:
    def __init__(self, account_id, p2p_public_key, url):
        self.account_id = account_id
        self.p2p_public_key = p2p_public_key
        self.url = url


def get_candidates(
        num_validators: int
) -> List[Candidate]:
    """
    Get the participant set from the mpc configs.
    """
    candidates = []
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for i, p in enumerate(participants_config['participants']):
        near_account = p['near_account_id']
        assert near_account == f"test{i + num_validators}", \
            f"This test only works with account IDs 'testX' where X is the node index; expected 'test{i + num_validators}', got {near_account}"
        p2p_public_key = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        candidates.append(Candidate(
            account_id=near_account,
            p2p_public_key=p2p_public_key,
            url=f"http://{my_addr}:{my_port}",
        ))
    return candidates


def move_mpc_configs(
        observers: List[LocalNode]
):
    """
    Rust code generates a folder per each participant, we want to move everything in one place
    Name of each folder is just a node index, e.g. 0, 1, 2, ...
    """
    for idx, observer in enumerate(observers):
        mpc_config_dir = dot_near / str(idx)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(('mv', os.path.join(mpc_config_dir, fname), observer.node_dir))


def start_cluster_with_mpc(
        num_validators,
        num_mpc_nodes,
        num_respond_aks,
        contract,
        presignatures_to_buffer=None,
        start_mpc_nodes=True
):
    validators, observers = start_neard_cluster_with_cleanup(
        num_validators,
        num_mpc_nodes,
    )

    generate_mpc_configs(
        num_mpc_nodes,
        num_validators,
        presignatures_to_buffer
    )

    candidates = get_candidates(num_validators)

    move_mpc_configs(observers)

    mpc_nodes = [
        MpcNode(near_node, candidate.url, candidate.p2p_public_key)
        for near_node, candidate in zip(observers, candidates)
    ]

    cluster = MpcCluster(main=NearAccount(validators[0]), secondary=NearAccount(validators[1]))

    # Set up the node's home directories
    for mpc_node in mpc_nodes:
        create_and_dump_responder_config(
            num_respond_aks,
            mpc_node,
            cluster
        )

    # Deploy the mpc contract
    cluster.deploy_contract(contract)

    # Name mpc nodes A, B, C, ...
    for i, mpc_node in enumerate(mpc_nodes):
        mpc_node.set_secret_store_key(str(chr(ord('A') + i) * 32))

    # Start the mpc nodes
    if start_mpc_nodes:
        for mpc_node in mpc_nodes:
            mpc_node.run()

    return cluster, mpc_nodes
