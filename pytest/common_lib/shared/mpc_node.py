import json
import pathlib
import sys
import time

from key import Key
from ruamel.yaml import YAML

from common_lib.constants import MPC_BINARY_PATH, TIMEOUT
from common_lib.shared.near_account import NearAccount

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode

from utils import MetricsTracker

import requests


class MpcNode(NearAccount):
    """
    MPC Node interface to keep track of the current status in the Chain-Signatures contract.
    Also, initial parameters for the binary is being controlled there.

    Mpc Node has its respective account on NEAR Blockchain.
    """

    class NodeStatus:
        # not a participant, neither a candidate
        IDLE = 1
        # a participant in the current epoch and also in the next epoch
        PARTICIPANT = 2
        # a participant in the current epoch but not in the next epoch
        OLD_PARTICIPANT = 3
        # a participant in the next epoch, but not the current epoch
        NEW_PARTICIPANT = 4

    def __init__(
            self,
            near_node: LocalNode,
            signer_key: Key,
            url,
            p2p_public_key
    ):
        super().__init__(near_node, signer_key)
        self.url = url
        self.p2p_public_key = p2p_public_key
        self.status = MpcNode.NodeStatus.IDLE
        self.participant_id = None
        self.home_dir = self.near_node.node_dir
        self.is_running = False
        self.metrics = MetricsTracker(near_node)

    def change_contract_id(self, new_contract_id: str):
        yaml = YAML()
        yaml.preserve_quotes = True  # optional: keeps any quotes if present in original file

        path = pathlib.Path(self.home_dir) / 'config.yaml'
        with path.open('r') as f:
            config = yaml.load(f)

        old_contract_id = config['indexer']['mpc_contract_id']
        print(
            f"changing contract_id from {old_contract_id} to {new_contract_id} for node {self.account_id()}"
        )
        config['indexer']['mpc_contract_id'] = new_contract_id

        with path.open('w') as f:
            yaml.dump(config, f)

    def print(self):
        if not self.is_running:
            return f"⛔\033[90m{self.account_id()}\033[0m"

        status_map = {
            MpcNode.NodeStatus.IDLE: ("⚫", "90"),
            MpcNode.NodeStatus.PARTICIPANT: ("🟢", "92"),
            MpcNode.NodeStatus.OLD_PARTICIPANT: ("🟢", "92"),
            MpcNode.NodeStatus.NEW_PARTICIPANT: ("🟡", "93"),
        }

        symbol, color = status_map.get(self.status, ("❓", "90"))
        return f"{symbol}\033[{color}m{self.account_id()}\033[0m"

    def set_secret_store_key(self, secret_store_key):
        self.secret_store_key = secret_store_key

    def reset_mpc_data(self):
        assert not self.is_running
        patterns = [
            'CURRENT',
            'IDENTITY'
            'LOCK',
            'LOG',
            'MANIFEST-.*',
            'OPTIONS-.*',
            '*.log',
            '*.sst',
        ]
        for pattern in patterns:
            for file_path in pathlib.Path(self.home_dir).glob(pattern):
                file_path.unlink()

    def run(self):
        assert not self.is_running
        self.is_running = True
        extra_env = {
            'RUST_LOG': 'INFO',  # mpc-node produces too much output on DEBUG
            'MPC_SECRET_STORE_KEY': self.secret_store_key,
        }
        cmd = (MPC_BINARY_PATH, 'start', '--home-dir', self.home_dir)
        self.near_node.run_cmd(cmd=cmd, extra_env=extra_env)

    def kill(self, gentle=True):
        self.near_node.kill(gentle=gentle)
        self.is_running = False

    def wait_for_connection_count(self, awaited_count):
        started = time.time()
        while True:
            assert time.time() - started < TIMEOUT, "Waiting for connection count"
            try:
                conns = self.metrics.get_metric_all_values(
                    "mpc_network_live_connections")
                print("mpc_network_live_connections", conns)
                connection_count = int(sum([kv[1] for kv in conns]))
                if connection_count == awaited_count:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(1)

    def reserve_key_event_attempt(self, epoch_id, domain_id, attempt_id):
        file_path = pathlib.Path(self.home_dir)
        file_path = file_path / "temporary_keys" / f"started_{epoch_id}_{domain_id}_{attempt_id}"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch()
