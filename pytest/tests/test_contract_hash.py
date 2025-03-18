import hashlib
import sys
import pathlib
from utils import load_binary_file
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib.contracts import CURRENT_CONTRACT_VERSION, COMPILED_CONTRACT_PATH


@pytest.mark.skip(
    reason=
    "Compilation is platform specific. Also, migrating to contract v2, do not change the v1 binary anymore"
)
def test_current_contract_hash():
    """
    Checks if the sha256 hash of the file in `COMPILED_CONTRACT_PATH` matches the hash of the `CURRENT_CONTRACT_VERSION`
    """
    current_contract = load_binary_file(COMPILED_CONTRACT_PATH)
    expected_contract = load_binary_file(CURRENT_CONTRACT_VERSION)
    hash_expected = hashlib.sha256(expected_contract).hexdigest()
    hash_compiled = hashlib.sha256(current_contract).hexdigest()
    assert hash_expected == hash_compiled, "hash of compiled contract did not match hash of expected contract"
