from dataclasses import asdict, dataclass
import enum
import json
import pathlib
import sys
import time
from typing import Any, cast

from key import Key


from common_lib.constants import LISTEN_BLOCKS_FILE, MPC_BINARY_PATH
from common_lib.contracts import ContractMethod
from common_lib.migration_state import (
    BackupServiceInfo,
    DestinationNodeInfo,
    MigrationState,
    parse_migration_state,
)
from common_lib.shared import metrics
from common_lib.shared.metrics import DictMetricName, IntMetricName
from common_lib.shared.near_account import NearAccount

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode

from utils import MetricsTracker

import requests

DUMMY_MPC_IMAGE_HASH = "deadbeef" * 8


@dataclass
class SocketAddress:
    host: str
    port: str

    @staticmethod
    def from_config(config_section: Any) -> "SocketAddress":
        return SocketAddress(
            host=config_section.get("host"), port=config_section.get("port")
        )

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    def __repr__(self) -> str:
        return f"{self.host}:{self.port}"


class MpcNode(NearAccount):
    """
    MPC Node interface to keep track of the current status in the Chain-Signatures contract.
    Also, initial parameters for the binary is being controlled there.

    Mpc Node has its respective account on NEAR Blockchain.
    """

    class NodeStatus(enum.IntEnum):
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
        p2p_url: str,
        web_address: SocketAddress,
        migration_address: SocketAddress,
        p2p_public_key: str,
        pytest_signer_keys: list[Key],
        backup_key: bytes,
    ):
        super().__init__(near_node, signer_key, pytest_signer_keys)
        self.p2p_url: str = p2p_url
        self.web_address: SocketAddress = web_address
        self.migration_address: SocketAddress = migration_address
        self.p2p_public_key: str = p2p_public_key
        self.status: MpcNode.NodeStatus = MpcNode.NodeStatus.IDLE
        self.participant_id: int | None = None
        self.home_dir = self.near_node.node_dir
        self.is_running = False
        self.metrics = MetricsTracker(near_node)
        self.backup_key = backup_key

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

    def migration_state_from_web(self) -> MigrationState:
        response = requests.get(f"http://{self.web_address}/debug/migrations")
        (_, contract_btree_map) = json.loads(response.text)
        return parse_migration_state(contract_btree_map)

    def wait_for_migration_state(
        self, expected_migrations: MigrationState, max_wait_duration_sec: int = 10
    ):
        start = time.time()
        while True:
            current_state = self.migration_state_from_web()
            if current_state == expected_migrations:
                return
            else:
                assert time.time() < start + max_wait_duration_sec, (
                    f"Expected {expected_migrations}, found: {current_state}"
                )
                time.sleep(1)

    def reset_mpc_data(self):
        assert not self.is_running
        patterns = [
            "CURRENT",
            "IDENTITY",
            "LOCK",
            "LOG",
            "MANIFEST-.*",
            "OPTIONS-.*",
            "*.log",
            "*.sst",
        ]
        for pattern in patterns:
            for file_path in pathlib.Path(self.home_dir).glob(pattern):
                file_path.unlink()

    def run(self):
        assert not self.is_running
        self.is_running = True
        extra_env = {
            "RUST_LOG": "INFO",  # mpc-node produces too much output on DEBUG
            "MPC_SECRET_STORE_KEY": self.secret_store_key,
            "MPC_IMAGE_HASH": DUMMY_MPC_IMAGE_HASH,
            "MPC_LATEST_ALLOWED_HASH_FILE": "latest_allowed_hash.txt",
            "MPC_BACKUP_ENCRYPTION_KEY_HEX": self.backup_key.hex(),
        }
        cmd = (
            MPC_BINARY_PATH,
            "start",
            "--home-dir",
            self.home_dir,
            "local",
        )
        self.near_node.run_cmd(cmd=cmd, extra_env=extra_env)

    def kill(self, gentle=True):
        self.near_node.kill(gentle=gentle)
        self.is_running = False

    def restart(self, gentle=True):
        self.kill(gentle=gentle)
        self.run()

    def assert_num_live_connections(self, expected_count: int, timeout: int):
        started = time.time()
        last_print = -1.5
        while True:
            elapsed = time.time() - started
            assert elapsed < timeout, (
                f"Node {self.print()} did not reach expected connection count before timeout."
            )
            try:
                conns = self.metrics.get_metric_all_values(
                    metrics.DictMetricName.MPC_NETWORK_LIVE_CONNECTIONS,
                )
                connection_count = int(sum([int(kv[1]) for kv in conns]))
                if elapsed - last_print >= 1.5:
                    print(f"Node {self.print()} connected to {connection_count} nodes.")
                    last_print = elapsed
                if connection_count == expected_count:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(0.1)

    def reserve_key_event_attempt(self, epoch_id, domain_id, attempt_id):
        file_path = pathlib.Path(self.home_dir)
        file_path = (
            file_path
            / "temporary_keys"
            / f"started_{epoch_id}_{domain_id}_{attempt_id}"
        )
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch()

    def set_block_ingestion(self, value: bool):
        file_path = pathlib.Path(self.home_dir)
        file_path = file_path / LISTEN_BLOCKS_FILE
        print(f"setting {file_path} to {value}")
        file_path.write_text(str(value).lower())

    def get_int_metric_value(self, metric: IntMetricName) -> int | None:
        return self.metrics.get_int_metric_value(metric)

    def require_int_metric_value(self, metric_name: IntMetricName) -> int:
        """
        Returns the integer value of metrict `metric_name` for this node.
        Panics if the received value is None.
        """
        value: int | None = self.get_int_metric_value(metric_name)
        if value is None:
            raise ValueError(
                f"expected integer values for {metric_name} at node {self.print()}"
            )
        return cast(int, value)

    def get_peers_block_height_metric_value(self) -> dict[int, int]:
        res = self.metrics.get_metric_all_values(
            DictMetricName.MPC_PEERS_INDEXER_BLOCK_HEIGHTS
        )
        return {int(a["participant"]): int(b) for a, b in res}

    def set_backup_service_info(
        self, contract: str, backup_service_info: BackupServiceInfo
    ):
        tx = self.sign_tx(
            contract,
            ContractMethod.REGISTER_BACKUP_SERVICE,
            {"backup_service_info": asdict(backup_service_info)},
        )
        return self.send_txn_and_check_success(tx)

    def start_node_migration(
        self, contract: str, destination_node_info: DestinationNodeInfo
    ):
        tx = self.sign_tx(
            contract,
            ContractMethod.START_NODE_MIGRATION,
            {"destination_node_info": asdict(destination_node_info)},
        )
        return self.send_txn_and_check_success(tx)
