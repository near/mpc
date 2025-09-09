import json
import os
import pathlib
import subprocess
import sys
from typing import List, Optional, Tuple, cast
import typing

import base58
import yaml
from nacl.signing import SigningKey

from common_lib.constants import NEAR_BASE, MPC_BINARY_PATH
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode
from common_lib.shared.near_account import NearAccount
from common_lib.shared.transaction_status import assert_txn_success
from common_lib.shared.yaml_safeloader import SafeLoaderIgnoreUnknown

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import start_cluster, LocalNode

from transaction import (
    create_create_account_action,
    create_payment_action,
    create_full_access_key_action,
    # create_mpc_function_call_access_key_action
    sign_transaction,
    serialize_transaction,
    Action,
    AccessKey,
    AccessKeyPermission,
    FunctionCallPermission,
    PublicKey,
    AddKey,
)


from key import Key

dot_near = pathlib.Path.home() / ".near"
SECRETS_JSON = "secrets.json"


def create_function_call_access_key_action(
    pk: str, contract_id: str, method_names: list[str], allowance: int | None = None
) -> "Action":
    permission = AccessKeyPermission()
    permission.enum = "functionCall"

    fc_perm = FunctionCallPermission()
    fc_perm.allowance = allowance
    fc_perm.receiverId = contract_id
    fc_perm.methodNames = method_names
    permission.functionCall = fc_perm

    access_key = AccessKey()
    access_key.nonce = 0
    access_key.permission = permission

    public_key = PublicKey()
    public_key.keyType = 0
    public_key.data = pk

    add_key = AddKey()
    add_key.accessKey = access_key
    add_key.publicKey = public_key

    action = Action()
    action.enum = "addKey"
    action.addKey = add_key

    return action


def create_mpc_function_call_access_key_action(
    pk: str, contract_id: str, allowance: int | None = None
) -> "Action":
    """
    Create a restricted access key that only allows calling MPC-related contract methods.
    """
    mpc_methods_used_by_node = [
        "respond",
        "respond_ckd",
        "vote_pk",
        "start_keygen_instance",
        "vote_reshared",
        "start_reshare_instance",
        "vote_abort_key_event_instance",
        "verify_tee",
        "submit_participant_info",
        "vote_add_domains",
        "vote_cancel_resharing",
    ]

    return create_function_call_access_key_action(
        pk=pk,
        contract_id=contract_id,
        method_names=mpc_methods_used_by_node,
        allowance=allowance,
    )


# Output is deserializable into the rust type near_sdk::SecretKey
def serialize_key(key: bytes) -> str:
    key_bytes = bytes(key)
    return "ed25519:" + base58.b58encode(key_bytes).decode("ascii")


def deserialize_key(account_id: str, key: List[int]) -> Key:
    key_bytes = bytes(key)
    signing_key = SigningKey(key_bytes)
    return Key.from_keypair(account_id, signing_key)


def sign_create_account_with_multiple_access_keys_tx(
    creator_key: Key,
    new_account_id,
    keys: List[Key],
    nonce,
    block_hash,
    contract_id,
    fullAccess: bool,
    createNewAccount: bool,
) -> bytes:
    actions = []

    if createNewAccount:
        # Only when creating a brand-new account
        actions.append(create_create_account_action())
        actions.append(create_payment_action(100 * NEAR_BASE))

    if fullAccess:
        # Give full access to all keys
        access_key_actions = [
            create_full_access_key_action(key.decoded_pk()) for key in keys
        ]
    else:
        # Give restricted MPC-only access to all keys
        access_key_actions = [
            create_mpc_function_call_access_key_action(key.decoded_pk(), contract_id)
            for key in keys
        ]

    actions.extend(access_key_actions)

    signed_tx = sign_transaction(
        new_account_id,
        nonce,
        actions,
        block_hash,
        creator_key.account_id,
        creator_key.decoded_pk(),
        creator_key.decoded_sk(),
    )
    return serialize_transaction(signed_tx)


def start_neard_cluster_with_cleanup(
    num_validators: int,
    num_mpc_nodes: int,
) -> Tuple[List[LocalNode], List[LocalNode]]:
    rpc_polling_config = {
        "rpc": {
            "polling_config": {
                "polling_timeout": {"secs": 20, "nanos": 0},
                "polling_interval": {"secs": 0, "nanos": 10000000},
            }
        }
    }

    client_config_changes = {
        0: rpc_polling_config,
        1: rpc_polling_config,
    }

    # the config is set to local, so we expect local nodes.
    nodes: typing.List[LocalNode] = cast(
        List[LocalNode],
        start_cluster(
            num_validators,
            num_mpc_nodes,
            1,
            None,
            [("epoch_length", 1000), ("block_producer_kickout_threshold", 80)],
            client_config_changes=client_config_changes,
        ),
    )

    validators = nodes[:num_validators]
    observers = nodes[num_validators:]

    for observer in observers:
        observer.kill(gentle=True)
        observer.reset_data()
        adjust_indexing_shard(observer)

    return validators, observers


class Candidate:
    def __init__(
        self,
        signer_key: Key,
        responder_keys: list[Key],
        p2p_public_key,
        url,
    ):
        self.signer_key = signer_key
        self.responder_keys = responder_keys
        self.p2p_public_key = p2p_public_key
        self.url = url


def generate_mpc_configs(
    num_mpc_nodes: int,
    num_respond_aks: int,
    presignatures_to_buffer: Optional[int],
) -> List[Candidate]:
    """
    Generate MPC configs for each participant.
    Without loss of generality, we will make all MPC participant's near account a subaccount of the main (contract) node.
    This will make things easier. Otherwise:
    FIXME: the canonical way is to create completely new accounts via registrar account.
      (1) How to get it via py api?
      (2) observer nodes that corresponds to the mpc participant hasn't been started yet,
        so we can not make any requests from them yet.
    """
    signers = ",".join(f"signer_{i}.test0" for i in range(num_mpc_nodes))
    responders = [f"responder_{i}.test0" for i in range(num_mpc_nodes)]
    cmd = (
        MPC_BINARY_PATH,
        "generate-test-configs",
        "--output-dir",
        dot_near,
        "--participants",
        signers,
        "--responders",
        ",".join(responders),
        "--threshold",
        str(num_mpc_nodes),
        "--desired-responder-keys-per-participant",
        str(num_respond_aks),
    )
    if presignatures_to_buffer:
        cmd = cmd + (
            "--desired-presignatures-to-buffer",
            str(presignatures_to_buffer),
        )
    subprocess.run(cmd)

    candidates = []
    with open(pathlib.Path(dot_near / "participants.json")) as file:
        participants_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for idx, (participant, responder_account_id) in enumerate(
        zip(
            participants_config["participants"],
            responders,
        )
    ):
        near_account = participant["near_account_id"]
        p2p_public_key = participant["p2p_public_key"]
        p2p_public_key_near_sdk_representation = serialize_key(p2p_public_key)

        my_addr = participant["address"]
        my_port = participant["port"]

        secrets_file_path = os.path.join(dot_near, str(idx), SECRETS_JSON)
        with open(secrets_file_path) as file:
            participant_secrets = json.load(file)
        signer_key = deserialize_key(
            near_account,
            participant_secrets["near_signer_key"],
        )
        responder_keys = []
        for key in participant_secrets["near_responder_keys"]:
            responder_keys.append(deserialize_key(responder_account_id, key))

        candidates.append(
            Candidate(
                signer_key=signer_key,
                responder_keys=responder_keys,
                p2p_public_key=p2p_public_key_near_sdk_representation,
                url=f"http://{my_addr}:{my_port}",
            )
        )
    return candidates


def adjust_indexing_shard(near_node: LocalNode):
    """Set the node to track all shards in config.json (any non-empty list for 'tracked_shards' will make the node observe all shards)."""
    path = os.path.join(near_node.node_dir, "config.json")

    with open(path, "r+") as f:
        config = json.load(f)
        config["tracked_shards_config"] = "AllShards"
        f.seek(0)
        json.dump(config, f, indent=2)
        f.truncate()

    print(f"Updated near node config: {path}")


def move_mpc_configs(observers: List[LocalNode]):
    """
    Rust code generates a folder per each participant, we want to move everything in one place
    Name of each folder is just a node index, e.g. 0, 1, 2, ...
    """
    for idx, observer in enumerate(observers):
        mpc_config_dir = dot_near / str(idx)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(
                (
                    "mv",
                    os.path.join(mpc_config_dir, fname),
                    observer.node_dir,
                )
            )


def start_cluster_with_mpc(
    num_validators,
    num_mpc_nodes,
    num_respond_aks,
    contract,
    presignatures_to_buffer=None,
    start_mpc_nodes=True,
):
    validators, observers = start_neard_cluster_with_cleanup(
        num_validators,
        num_mpc_nodes,
    )

    candidates = generate_mpc_configs(
        num_mpc_nodes, num_respond_aks, presignatures_to_buffer
    )

    move_mpc_configs(observers)

    cluster = MpcCluster(
        main=NearAccount(
            validators[0],
            validators[0].signer_key,
            [validators[0].signer_key],
        ),
        secondary=NearAccount(
            validators[1],
            validators[1].signer_key,
            [validators[1].signer_key],
        ),
    )

    (key, nonce) = cluster.contract_node.get_key_and_nonce()
    # --- Phase 1: create accounts + add pytest keys ---
    txs_phase1 = []
    mpc_nodes = []

    for near_node, candidate in zip(observers, candidates):
        candidate_account_id = candidate.signer_key.account_id
        pytest_signer_keys = []

        # Responder account (new account, responder access keys)
        nonce += 1
        tx = sign_create_account_with_multiple_access_keys_tx(
            key,
            candidate.responder_keys[0].account_id,
            candidate.responder_keys,
            nonce,
            cluster.contract_node.last_block_hash(),
            cluster.mpc_contract_account(),
            False,  # restricted access
            True,  # create new account
        )
        txs_phase1.append(tx)

        # Generate pytest signing keys (local only, for later TXs)
        for i in range(5):
            pytest_signing_key: SigningKey = SigningKey.generate()
            pytest_signer_key: Key = Key.from_keypair(
                candidate_account_id,
                pytest_signing_key,
            )
            pytest_signer_keys.append(pytest_signer_key)

        # Add pytest keys to candidate account
        nonce += 1
        tx = sign_create_account_with_multiple_access_keys_tx(
            key,
            candidate_account_id,
            pytest_signer_keys,
            nonce,
            cluster.contract_node.last_block_hash(),
            cluster.mpc_contract_account(),
            True,  # full access
            True,  # new account
        )
        txs_phase1.append(tx)

        # Build MPC node but don’t add node key yet
        mpc_node = MpcNode(
            near_node,
            candidate.signer_key,
            candidate.url,
            candidate.p2p_public_key,
            pytest_signer_keys,
        )
        mpc_node.set_block_ingestion(True)
        mpc_nodes.append(mpc_node)

    # 🚀 Send + wait for Phase 1 TXs
    cluster.contract_node.send_await_check_txs_parallel(
        "phase1: create accounts + pytest keys", txs_phase1, assert_txn_success
    )

    # --- Phase 2: add node access key (signed by pytest key which now exists) ---
    txs_phase2 = []

    for mpc_node, candidate in zip(mpc_nodes, candidates):
        nonce += 1
        tx = sign_create_account_with_multiple_access_keys_tx(
            key,
            candidate.signer_key.account_id,
            [candidate.signer_key],
            nonce,
            cluster.contract_node.last_block_hash(),
            cluster.mpc_contract_account(),
            False,  # restricted access
            False,  # account already exists
        )
        txs_phase2.append(tx)

    cluster.contract_node.send_await_check_txs_parallel(
        "phase2: add node keys", txs_phase2, assert_txn_success
    )

    # Deploy the mpc contract
    cluster.deploy_contract(contract)

    # Name mpc nodes A, B, C, ...
    for i, mpc_node in enumerate(mpc_nodes):
        mpc_node.set_secret_store_key(str(chr(ord("A") + i) * 32))

    # Start the mpc nodes
    if start_mpc_nodes:
        for mpc_node in mpc_nodes:
            mpc_node.run()

    return cluster, mpc_nodes
