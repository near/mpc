#/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract.
Deploys a test contract with a function that makes parallel sign calls.
Calls the test function and ensures a successful response.
"""

import sys
import time
import base64
import pytest
import pathlib
from utils import load_binary_file

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts, constants


def load_parallel_sign_contract() -> bytearray:
    """
    returns test contract for parallel sign
    """
    path = constants.MPC_REPO_DIR / 'pytest/tests/test_contracts/parallel/res/contract.wasm'
    return load_binary_file(path)


@pytest.mark.parametrize("num_parallel_signatures", [5])
def test_parallel_sign_calls(num_parallel_signatures):
    # start cluster and deploy mpc contract
    mpc_contract = contracts.load_mpc_contract()
    cluster = shared.start_cluster_with_mpc(2, 2, 1, mpc_contract)
    cluster.init_contract(threshold=2)

    # deploy contract with function that makes parallel sign calls
    contract = load_parallel_sign_contract()
    cluster.deploy_secondary_contract(contract)

    # call `parallel_sign` and verify that it returns successfully
    res = cluster.make_function_call_on_secondary_contract(
        function_name='make_parallel_sign_calls',
        args={
            'target_contract': cluster.mpc_contract_account(),
            'num_calls': num_parallel_signatures,
            'seed': 23,
        })

    # check the return value
    encoded_value = res['result']['status']['SuccessValue']
    decoded_value = base64.b64decode(encoded_value).decode("utf-8")
    assert int(decoded_value) == num_parallel_signatures
