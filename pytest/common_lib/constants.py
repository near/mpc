import pathlib
import os

mpc_repo_dir = pathlib.Path(__file__).resolve().parents[2]
mpc_binary_path = os.path.join(mpc_repo_dir / 'target' / 'release', 'mpc-node')

TIMEOUT = 60
NEAR_BASE = 10**24
TGAS = 10**12
# gas required by the contract for a sign call.
GAS_FOR_SIGN_CALL = 50
# maximum number of requests that can be removed during a sign / request call.
MAX_NUM_REQUSTS_TO_REMOVE = 100
