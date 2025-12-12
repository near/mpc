from dataclasses import dataclass
import json
import os
import pathlib
import subprocess
import sys
from typing import cast
import time
import requests
from concurrent.futures import ThreadPoolExecutor

import base58
import yaml
from nacl.signing import SigningKey

from common_lib.constants import NEAR_BASE, MPC_BINARY_PATH
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode, SocketAddress
from common_lib.shared.near_account import NearAccount
from common_lib.shared.transaction_status import assert_txn_success
from common_lib.shared.yaml_safeloader import SafeLoaderIgnoreUnknown
from common_lib.shared.metrics import IntMetricName, NodeMetrics

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import start_cluster, LocalNode

from transaction import (
    create_create_account_action,
    create_payment_action,
    create_full_access_key_action,
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
NUMBER_OF_VALIDATORS = 1
CONFIG_YAML = "config.yaml"


def create_function_call_access_key_action(
    pk: bytes, contract_id: str, method_names: list[str], allowance: int | None = None
) -> Action:
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
    pk: bytes, contract_id: str, allowance: int | None = None
) -> Action:
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
        "conclude_node_migration",
    ]

    return create_function_call_access_key_action(
        pk=pk,
        contract_id=contract_id,
        method_names=mpc_methods_used_by_node,
        allowance=allowance,
    )


ED25519_PREFIX = "ed25519"


# Output is deserializable into the rust type near_sdk::SecretKey
def serialize_key(key: bytes) -> str:
    key_bytes = bytes(key)
    return f"{ED25519_PREFIX}:" + base58.b58encode(key_bytes).decode("ascii")


def deserialize_key(account_id: str, key: str) -> Key:
    assert key.startswith(f"{ED25519_PREFIX}:")
    key_bytes = base58.b58decode(key[len(ED25519_PREFIX) + 1 :])
    assert len(key_bytes) == 64
    signing_key = SigningKey(key_bytes[:32])
    return Key.from_keypair(account_id, signing_key)


#   Create a brand-new account and attach the given full access keys.
def sign_create_account_with_multiple_access_keys_tx(
    creator_key: Key,
    new_account_id: str,
    keys: list[Key],
    nonce: int,
    block_hash: bytes,
) -> bytes:
    actions = [
        create_create_account_action(),
        create_payment_action(100 * NEAR_BASE),
    ]
    actions.extend([create_full_access_key_action(key.decoded_pk()) for key in keys])

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


"""
    Add access keys to an existing account.
    Supports both full access keys and restricted  access keys.
"""


def sign_add_access_keys_tx(
    creator_key: Key,
    account_id: str,
    keys: list[Key],
    nonce: int,
    block_hash: bytes,
    contract_id: str,
    full_access: bool = False,
) -> bytes:
    if full_access:
        access_key_actions = [
            create_full_access_key_action(key.decoded_pk()) for key in keys
        ]
    else:
        access_key_actions = [
            create_mpc_function_call_access_key_action(
                key.decoded_pk(), contract_id, allowance=100 * NEAR_BASE
            )
            for key in keys
        ]

    signed_tx = sign_transaction(
        account_id,
        nonce,
        access_key_actions,
        block_hash,
        creator_key.account_id,
        creator_key.decoded_pk(),
        creator_key.decoded_sk(),
    )
    return serialize_transaction(signed_tx)


def kill_observer(observer: LocalNode):
    observer.kill(gentle=True)
    observer.reset_data()
    adjust_indexing_shard(observer)


def start_neard_cluster_with_cleanup(
    num_mpc_nodes: int,
) -> tuple[list[LocalNode], list[LocalNode]]:
    num_validators = NUMBER_OF_VALIDATORS
    rpc_polling_config = {
        "rpc": {
            "polling_config": {
                "polling_timeout": {"secs": 20, "nanos": 0},
                "polling_interval": {"secs": 0, "nanos": 10000000},
            }
        }
    }

    client_config_changes = {i: rpc_polling_config for i in range(num_validators)}

    # the config is set to local, so we expect local nodes.
    nodes: list[LocalNode] = cast(
        list[LocalNode],
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

    with ThreadPoolExecutor(max_workers=len(observers)) as executor:
        executor.map(lambda observer: kill_observer(observer), observers)

    return validators, observers


@dataclass
class ConfigValues:
    signer_key: Key
    responder_keys: list[Key]
    p2p_public_key: str
    p2p_url: str
    web_address: SocketAddress
    migration_address: SocketAddress
    backup_key: bytes


def generate_mpc_configs(
    num_mpc_nodes: int,
    num_respond_aks: int,
    presignatures_to_buffer: int | None,
    triples_to_buffer: int | None,
    migrating_nodes: list[int],
) -> list[ConfigValues]:
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

    if migrating_nodes:
        cmd += (
            "--migrating-nodes",
            ",".join(f"{i}" for i in migrating_nodes),
        )

    if presignatures_to_buffer:
        cmd += (
            "--desired-presignatures-to-buffer",
            str(presignatures_to_buffer),
        )

    if triples_to_buffer:
        cmd += (
            "--desired-triples-to-buffer",
            str(triples_to_buffer),
        )

    subprocess.run(cmd)

    for i in migrating_nodes:
        responders.append(responders[i])

    configs = []
    with open(pathlib.Path(dot_near / "participants.json")) as file:
        participants_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for idx, (participant, responder_account_id) in enumerate(
        zip(
            participants_config["participants"],
            responders,
        )
    ):
        near_account = participant["near_account_id"]
        p2p_public_key_raw = participant[
            "p2p_public_key"
        ]  # note: this is not really how it is done in production...
        p2p_public_key: str = serialize_key(p2p_public_key_raw)

        my_addr = participant["address"]
        my_port = participant["port"]
        p2p_url = f"http://{my_addr}:{my_port}"

        config_file_path = os.path.join(dot_near, str(idx), CONFIG_YAML)
        with open(config_file_path, "r") as f:
            config = yaml.load(f, Loader=SafeLoaderIgnoreUnknown)

        web_address = SocketAddress.from_config(config.get("web_ui"))
        migration_address = SocketAddress.from_config(config.get("migration_web_ui"))

        secrets_file_path = os.path.join(dot_near, str(idx), SECRETS_JSON)

        with open(secrets_file_path) as file:
            participant_secrets = json.load(file)

        signer_key = deserialize_key(
            near_account,
            participant_secrets["near_signer_key"],
        )

        responder_keys: list[Key] = [
            deserialize_key(responder_account_id, key)
            for key in participant_secrets["near_responder_keys"]
        ]

        backup_key = os.urandom(32)
        configs.append(
            ConfigValues(
                signer_key,
                responder_keys,
                p2p_public_key,
                p2p_url,
                web_address,
                migration_address,
                backup_key,
            )
        )
    return configs


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


def move_mpc_configs(observers: list[LocalNode]):
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
    num_mpc_nodes,
    num_respond_aks,
    contract,
    presignatures_to_buffer=None,
    triples_to_buffer=None,
    start_mpc_nodes=True,
    migrating_nodes=[],
):
    NUM_PYTEST_SIGNERS = 5

    validators, observers = start_neard_cluster_with_cleanup(
        num_mpc_nodes + len(migrating_nodes),
    )

    configs = generate_mpc_configs(
        num_mpc_nodes,
        num_respond_aks,
        presignatures_to_buffer,
        triples_to_buffer,
        migrating_nodes,
    )

    move_mpc_configs(observers)

    cluster = MpcCluster(
        main=NearAccount(
            validators[0],
            validators[0].signer_key,
            [validators[0].signer_key],
        ),
    )

    (key, nonce) = cluster.contract_node.get_key_and_nonce()
    create_txs = []
    access_txs = []
    mpc_nodes: list[MpcNode] = []
    pytest_keys_per_node = [[] for _ in configs]
    secondary_near_account: NearAccount | None = None

    num_candidates = len(configs) - len(migrating_nodes)
    for i in range(num_candidates):
        near_node = observers[i]
        config = configs[i]

        responder_keys = config.responder_keys
        try:
            pos = migrating_nodes.index(i)
        except ValueError:
            pass
        else:
            responder_keys += configs[num_candidates + pos].responder_keys

        nonce += 1
        tx = sign_create_account_with_multiple_access_keys_tx(
            key,
            config.responder_keys[0].account_id,
            responder_keys,
            nonce,
            cluster.contract_node.last_block_hash(),
        )
        create_txs.append(tx)

        candidate_account_id = config.signer_key.account_id
        pytest_signer_keys = generate_signer_keys(
            candidate_account_id, NUM_PYTEST_SIGNERS
        )
        nonce += 1

        last_pytest_signer_keys = []
        try:
            pos = migrating_nodes.index(i)
        except ValueError:
            pass
        else:
            last_pytest_signer_keys = generate_signer_keys(
                candidate_account_id, NUM_PYTEST_SIGNERS
            )
        # Observer nodes haven't started yet so we use cluster node to send txs
        # add pytest_signer_keys that are used for voting, need to access
        tx = sign_create_account_with_multiple_access_keys_tx(
            key,
            candidate_account_id,
            pytest_signer_keys + last_pytest_signer_keys,
            nonce,
            cluster.contract_node.last_block_hash(),
        )
        create_txs.append(tx)
        pytest_keys_per_node[i] = pytest_signer_keys
        try:
            pos = migrating_nodes.index(i)
        except ValueError:
            pass
        else:
            pytest_keys_per_node[num_candidates + pos] = last_pytest_signer_keys

    secondary_account_id = f"secondary.{cluster.contract_node.account_id()}"
    secondary_key: Key = new_signer_key(secondary_account_id)
    nonce += 1
    tx = sign_create_account_with_multiple_access_keys_tx(
        key,
        secondary_account_id,
        [secondary_key],
        nonce,
        cluster.contract_node.last_block_hash(),
    )
    create_txs.append(tx)
    secondary_near_account = NearAccount(
        validators[0],
        secondary_key,
        [secondary_key],
    )

    cluster.contract_node.send_await_check_txs_parallel(
        "create account", create_txs, assert_txn_success
    )

    if secondary_near_account is not None:
        cluster.secondary_contract_node = secondary_near_account

    for near_node, config, pytest_signer_keys in zip(
        observers, configs, pytest_keys_per_node
    ):
        candidate_account_id = config.signer_key.account_id

        creator_key = pytest_signer_keys[0]

        nonce = cluster.contract_node.near_node.get_nonce_for_pk(
            candidate_account_id, creator_key.pk
        )

        # add node access key
        tx = sign_add_access_keys_tx(
            pytest_signer_keys[0],
            candidate_account_id,
            [config.signer_key],
            nonce + 1,
            cluster.contract_node.last_block_hash(),
            cluster.mpc_contract_account(),
            full_access=False,
        )
        access_txs.append(tx)

        mpc_node = MpcNode(
            near_node=near_node,
            signer_key=config.signer_key,
            p2p_url=config.p2p_url,
            web_address=config.web_address,
            migration_address=config.migration_address,
            p2p_public_key=config.p2p_public_key,
            pytest_signer_keys=pytest_signer_keys,
            backup_key=config.backup_key,
        )
        mpc_node.set_block_ingestion(True)
        mpc_nodes.append(mpc_node)

    cluster.contract_node.send_await_check_txs_parallel(
        "access keys", access_txs, assert_txn_success
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


def new_signer_key(account_id: str) -> Key:
    signer_key: SigningKey = SigningKey.generate()
    return Key.from_keypair(
        account_id,
        signer_key,
    )


def generate_signer_keys(account_id: str, num_keys: int) -> list[Key]:
    signer_keys: list[Key] = [new_signer_key(account_id) for _ in range(num_keys)]
    return signer_keys


def get_metric_value_for_node(cluster: MpcCluster, metric_name: str, node_id: int):
    result = cluster.get_int_metric_value_for_node(metric_name, node_id)
    return result if result is not None else 0


def get_node_metrics_all_nodes(cluster: MpcCluster):
    number_nodes = len(cluster.mpc_nodes)

    network_metrics = [NodeMetrics(0, 0, 0, 0, 0) for _ in range(number_nodes)]
    for i in range(len(cluster.mpc_nodes)):
        network_metrics[i].queue_size = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_size", i
        )
        network_metrics[i].requests_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_requests_indexed", i
        )
        network_metrics[i].responses_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_responses_indexed", i
        )
        network_metrics[i].matching_responses_indexed = get_metric_value_for_node(
            cluster, "mpc_pending_signatures_queue_matching_responses_indexed", i
        )

        network_metrics[
            i
        ].mpc_cluster_failed_signatures_count = get_metric_value_for_node(
            cluster, IntMetricName.MPC_CLUSTER_FAILED_SIGNATURES_COUNT, i
        )

        network_metrics[i].queue_size += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_size", i
        )
        network_metrics[i].requests_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_requests_indexed", i
        )
        network_metrics[i].responses_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_responses_indexed", i
        )
        network_metrics[i].matching_responses_indexed += get_metric_value_for_node(
            cluster, "mpc_pending_ckds_queue_matching_responses_indexed", i
        )
        print(f"Node {i}: {network_metrics[i]}")
    return network_metrics


def get_queue_attemps_generated(cluster: MpcCluster):
    led_requests = cluster.get_int_metric_value(
        IntMetricName.MPC_PENDING_SIGNATURES_QUEUE_ATTEMPTS_GENERATED
    ) + cluster.get_int_metric_value(
        IntMetricName.MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED
    )
    return sum(a for a in led_requests if a is not None)


def assert_num_presignatures_available(
    cluster: MpcCluster, expected_num_presignatures_available: int, timeout_seconds: int
):
    """
    Asserts that the number of presignatures available for each node in the cluster is exactly `expected_num_presignatures_available`.
    Does so by comparing the metric value `MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE` with the expected value.
    Panics in case any of the metrics is unreachable or does not match the expected value before timeout is reached.
    """
    started = time.time()
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (available) before timeout."
        )
        try:
            presignature_count: list[int] = cluster.require_int_metric_values(
                IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
            )
            if int(elapsed) % 2:
                print("Available presignatures:", presignature_count)
            if all(
                x == expected_num_presignatures_available for x in presignature_count
            ):
                print(
                    f"time for reaching expected asset count (available): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        except ValueError:
            # this case might happen if the metric is not yet available
            pass
        time.sleep(0.1)


def assert_num_offline_online_presignatures(
    cluster: MpcCluster,
    nodes_idxs_to_verify: list[int],
    expected_num_presignatures_online: int,
    expected_num_presignatures_offline: int,
    timeout_seconds: int,
):
    """
    Asserts that each node with index in `nodes_idxs_to_verify`:
        - owns exactly `expected_num_presignatures_online` with online participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_ONLINE`)
        - owns exactly `expected_num_presignatures_offline` with offline participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT`)

    Fails in case any of the metrics is not reachable or does not match the expected value before `timeout`
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (online | offline) before timeout."
        )

        try:
            cleanup_done = all(
                (
                    node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    == expected_num_presignatures_online
                    and node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    == expected_num_presignatures_offline
                )
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify)
            )
            if elapsed - last_print >= 5:
                last_print = elapsed
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify):
                    node_name = node.print()
                    peers_block_heights = node.get_peers_block_height_metric_value()
                    print(f"node {node_name} peer block heights: {peers_block_heights}")

                    online = node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    offline = node.require_int_metric_value(
                        IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    print(
                        f"Asset count node {node_name}: (online {online} | offline {offline})"
                    )
            if cleanup_done:
                print(
                    f"time for reaching expected asset count (online | offline): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)


def assert_num_live_connections(
    cluster: MpcCluster,
    node_idxs: list[int],
    expected_num_connected: int,
    timeout_seconds: int,
):
    """
    Asserts that each node in node_idx is connected to exactly `expected_num_connected` peers.
    """
    for node_idx in node_idxs:
        cluster.mpc_nodes[node_idx].assert_num_live_connections(
            expected_num_connected, timeout_seconds
        )


def assert_indexer_lag(
    cluster: MpcCluster,
    faulty_node_idx: int,
    active_node_idxs: list[int],
    min_lag_blocks: int = 10,
    timeout_seconds: int = 120,
):
    """
    This function:
        - asserts that the nodes correctly expose the `metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT` metric
        - returns only after the indexer of the node with `faulty_node_idx` lags at least `min_lag_blocks` behind every active nodes.
    Raises an exception if the timeout is exceeded or if there is no valid metric
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            f"Timed out waiting for node {faulty_node_idx} to lag {min_lag_blocks} behind {active_node_idxs}."
        )
        try:
            block_heights: list[int] = cluster.require_int_metric_values(
                IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
            )
            if elapsed - last_print >= 5:
                print(f"Block heights: {block_heights}")
                last_print = elapsed
            faulty_node_height: int = block_heights[faulty_node_idx]
            node_considered_stalled = all(
                [
                    faulty_node_height + min_lag_blocks
                    <= block_heights[active_node_idx]
                    for active_node_idx in active_node_idxs
                ]
            )
            if node_considered_stalled:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)
