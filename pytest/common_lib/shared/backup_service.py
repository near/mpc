import atexit
from dataclasses import dataclass
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, cast

import base58
from common_lib.constants import BACKUP_SERVICE_BINARY_PATH, MPC_REPO_DIR
from common_lib.migration_state import BackupServiceInfo
from common_lib.shared.mpc_node import MpcNode

from nacl.signing import SigningKey

BackupServiceSecretsJson = dict[str, list[int]]


@dataclass
class BackupServiceSecrets:
    p2p_private_key: bytes
    near_signer_key: bytes
    local_storage_aes_key: bytes

    @staticmethod
    def from_dict(backup_json: BackupServiceSecretsJson) -> "BackupServiceSecrets":
        return BackupServiceSecrets(
            p2p_private_key=bytes(backup_json["p2p_private_key"]),
            near_signer_key=bytes(backup_json["near_signer_key"]),
            local_storage_aes_key=bytes(backup_json["local_storage_aes_key"]),
        )

    def near_public_key(self) -> str:
        sk = SigningKey(self.p2p_private_key)
        pk_bytes = sk.verify_key.encode()
        pk_b58 = base58.b58encode(pk_bytes).decode()
        return f"ed25519:{pk_b58}"


class BackupService:
    def __init__(self):
        base_dir = os.path.join(MPC_REPO_DIR / "pytest" / ".backup-services")
        os.makedirs(base_dir, exist_ok=True)
        self.home_dir = tempfile.mkdtemp(prefix="instance_", dir=base_dir)

        atexit.register(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self.home_dir, ignore_errors=True)

    def generate_keys(self):
        cmd = (
            BACKUP_SERVICE_BINARY_PATH,
            "--home-dir",
            self.home_dir,
            "generate-keys",
        )
        _ = subprocess.run(cmd, check=True)

    def get_keyshares(self, mpc_node: MpcNode):
        url: str = str(mpc_node.migration_address)
        p2p_key: str = mpc_node.p2p_public_key
        backup_encryption_key: bytes = mpc_node.backup_key
        cmd = (
            BACKUP_SERVICE_BINARY_PATH,
            "--home-dir",
            self.home_dir,
            "get-keyshares",
            "--mpc-node-address",
            url,
            "--mpc-node-p2p-key",
            p2p_key,
            "--backup-encryption-key-hex",
            backup_encryption_key.hex(),
        )
        _ = subprocess.run(cmd, check=True)

    def info(self) -> BackupServiceInfo:
        json_path = os.path.join(self.home_dir, "secrets.json")
        with open(json_path, "r") as f:
            secrets_json: BackupServiceSecretsJson = cast(
                BackupServiceSecretsJson, json.load(f)
            )

        backup_service_secrets = BackupServiceSecrets.from_dict(secrets_json)
        near_pubkey = backup_service_secrets.near_public_key()
        backup_service_info = BackupServiceInfo(near_pubkey)
        return backup_service_info

    def set_contract_state(self, contract_state: Any):
        json_path: str = os.path.join(self.home_dir, "contract_state.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(contract_state, f, indent=2, ensure_ascii=False)

    def put_keyshares(self, mpc_node: MpcNode):
        url: str = str(mpc_node.migration_address)
        p2p_key: str = mpc_node.p2p_public_key
        backup_encryption_key: bytes = mpc_node.backup_key
        cmd = (
            BACKUP_SERVICE_BINARY_PATH,
            "--home-dir",
            self.home_dir,
            "put-keyshares",
            "--mpc-node-address",
            url,
            "--mpc-node-p2p-key",
            p2p_key,
            "--backup-encryption-key-hex",
            backup_encryption_key.hex(),
        )
        _ = subprocess.run(cmd, check=True)
