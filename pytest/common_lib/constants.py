import pathlib
import os

MPC_REPO_DIR = pathlib.Path(__file__).resolve().parents[2]
MPC_BINARY_PATH = os.path.join(MPC_REPO_DIR / 'target' / 'release', 'mpc-node')
CONFIG_PATH = os.path.join(MPC_REPO_DIR / 'pytest' / 'config.json')

TIMEOUT = 60
NEAR_BASE = 10**24
TGAS = 10**12
# Tgas required by the contract for a sign call.
GAS_FOR_SIGN_CALL = 10
SIGNATURE_DEPOSIT = 0
