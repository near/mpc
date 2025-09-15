import json

from utils import load_binary_file
from enum import Enum
from borsh_construct import Vec, U8, CStruct, U64, Option
from .constants import MPC_REPO_DIR

MIGRATE_CONTRACT_PACKAGE_NAME = "test-migration-contract"
PARALLEL_CONTRACT_PACKAGE_NAME = "test-parallel-contract"

COMPILED_CONTRACT_PATH = (
    MPC_REPO_DIR / "target" / "release-contract" / "mpc_contract.wasm"
)

TESTNET_ACCOUNT_ID = "v1.signer-prod.testnet"
MAINNET_ACCOUNT_ID = "v1.signer"


def build_view_code_request(account_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "query",
        "params": {
            "request_type": "view_code",
            "finality": "final",
            "account_id": account_id,
        },
    }


def load_mpc_contract() -> bytearray:
    """
    Returns the current contract.
    """
    return load_binary_file(COMPILED_CONTRACT_PATH)


class ConfigV2:
    def __init__(self, max_num_requests_to_remove, request_timeout_blocks):
        self.max_num_requests_to_remove = max_num_requests_to_remove
        self.request_timeout_blocks = request_timeout_blocks

    def dump_json(self):
        return json.dumps(
            {
                "request_timeout_blocks": self.max_num_requests_to_remove,
                "key_event_timeout_blocks": self.request_timeout_blocks,
            }
        )

    def get(self):
        return {
            "max_num_requests_to_remove": self.max_num_requests_to_remove,
            "request_timeout_blocks": self.request_timeout_blocks,
        }


ConfigV2Borsh = CStruct("key_event_timeout_blocks" / U64)
ProposeUpdateArgsV2 = CStruct(
    "code" / Option(Vec(U8)), "config" / Option(ConfigV2Borsh)
)


class UpdateArgsV2:
    def __init__(self, code_path=None, config=None):
        self.code_path = code_path
        self.config = config
        self._code = None

    def borsh_serialize(self):
        return ProposeUpdateArgsV2.build(
            {
                "code": self.code(),
                "config": self.config.get() if self.config is not None else None,
            }
        )

    def code(self):
        if self.code_path is None:
            return None
        if self._code is None:
            self._code = load_binary_file(self.code_path)
        return self._code

    def dump_json(self):
        assert self.config is not None
        return self.config.dump_json()


class ContractMethod(str, Enum):
    VOTE_NEW_PARAMETERS = "vote_new_parameters"
    VOTE_ADD_DOMAINS = "vote_add_domains"
    PROPOSE_UPDATE = "propose_update"
    VOTE_UPDATE = "vote_update"
