from utils import load_binary_file
from enum import Enum
from .constants import MPC_REPO_DIR

PARALLEL_CONTRACT_PACKAGE_NAME = "test-parallel-contract"
MPC_CONTRACT_PACKAGE_NAME = "mpc-contract"

MPC_CONTRACT_MANIFEST_PATH = MPC_REPO_DIR / "crates" / "contract" / "Cargo.toml"


def contract_compiled_file_name(contract_package_name: str) -> str:
    return f"{contract_package_name.replace('-', '_')}.wasm"


COMPILED_CONTRACT_DIRECTORY = (
    MPC_REPO_DIR / "target" / "wasm32-unknown-unknown" / "release-contract"
)


PARALLEL_CONTRACT_BINARY_PATH = (
    COMPILED_CONTRACT_DIRECTORY
    / contract_compiled_file_name(PARALLEL_CONTRACT_PACKAGE_NAME)
)

MPC_CONTRACT_BINARY_PATH = COMPILED_CONTRACT_DIRECTORY / contract_compiled_file_name(
    MPC_CONTRACT_PACKAGE_NAME
)


def load_mpc_contract() -> bytearray:
    """
    Returns the current contract.
    """
    return load_binary_file(MPC_CONTRACT_BINARY_PATH)


def load_parallel_sign_contract() -> bytearray:
    """
    Returns test contract for parallel sign
    """
    return load_binary_file(PARALLEL_CONTRACT_BINARY_PATH)


class ContractMethod(str, Enum):
    VOTE_NEW_PARAMETERS = "vote_new_parameters"
    VOTE_ADD_DOMAINS = "vote_add_domains"
    GET_TEE_ACCOUNTS = "get_tee_accounts"
    MIGRATION_INFO = "migration_info"
    STATE = "state"
    REGISTER_BACKUP_SERVICE = "register_backup_service"
    START_NODE_MIGRATION = "start_node_migration"
    CONFIG = "config"
