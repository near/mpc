import pathlib
import os

MPC_REPO_DIR = pathlib.Path(__file__).resolve().parents[2]
MPC_BINARY_PATH = os.path.join(MPC_REPO_DIR / "target" / "release", "mpc-node")
BACKUP_SERVICE_BINARY_PATH = os.path.join(
    MPC_REPO_DIR / "target" / "release", "backup-cli"
)
CONFIG_PATH = os.path.join(MPC_REPO_DIR / "pytest" / "config.json")

LISTEN_BLOCKS_FILE = "listen_blocks.flag"

TIMEOUT = 60
SHORT_TIMEOUT = 10
NEAR_BASE = 10**24
TGAS = 10**12
# Tgas required by the contract for a sign call. If this needs modification, ENSURE THE CONSTANT IN THE CONTRACT AND THE TX-BENCH TOOL ALSO GETS ADJUSTED!
GAS_FOR_SIGN_CALL = 15
# Tgas required by the contract for a ckd call. If this needs modification, ENSURE THE CONSTANT IN THE CONTRACT AND THE TX-BENCH TOOL ALSO GETS ADJUSTED!
GAS_FOR_CKD_CALL = 15
# Deposit in Yoctonear required for a sign call.
SIGNATURE_DEPOSIT = 1
# Deposit in Yoctonear required for a ckd call.
CKD_DEPOSIT = 1
# maximum block delay an MPC node is allowed to communicated before being labeled offline
# defined in https://github.com/near/mpc/blob/cf53eadb8a9a5ad73da07efc0e8cb206af6fb48f/node/src/network.rs#L103
INDEXER_MAX_HEIGHT_DIFF = 50
