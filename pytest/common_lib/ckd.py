import pathlib
import sys
import json
import base64
import base58
from cryptography.hazmat.primitives.asymmetric import ec

from typing import Optional

from common_lib.contract_state import Domain

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))


def assert_ckd_success(res):
    try:
        ck_base64 = res["result"]["status"]["SuccessValue"]
    except KeyError:
        raise AssertionError(json.dumps(res, indent=1))

    ck_base64 += "=" * ((4 - len(ck_base64) % 4) % 4)
    ck = json.loads(base64.b64decode(ck_base64))
    print("\033[96mCKD Response ✓\033[0m")
    return ck


# This function cannot simply return a fixed point because
# some of our tests use concurrent ckd requests, and the indexer
# currently optimizes away identical requests
def generate_app_public_key() -> str:
    def b58encode(x, y):
        coordinate_length = 32
        x_bytes = x.to_bytes(coordinate_length, byteorder="big")
        y_bytes = y.to_bytes(coordinate_length, byteorder="big")
        return "secp256k1:" + base58.b58encode(x_bytes + y_bytes).decode("ascii")

    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    pk = public_key.public_numbers()
    pk = b58encode(pk.x, pk.y)
    return pk


def generate_ckd_args(domain: Domain, app_public_key: Optional[str] = None) -> dict:
    assert domain.scheme == "Secp256k1"
    if app_public_key is None:
        app_public_key = generate_app_public_key()
    return {"request": {"domain_id": domain.id, "app_public_key": app_public_key}}


def print_ckd_outcome(res):
    try:
        ck_base64 = res["result"]["status"]["SuccessValue"]
    except KeyError:
        raise AssertionError(json.dumps(res, indent=1))

    ck_base64 += "=" * ((4 - len(ck_base64) % 4) % 4)
    ck = json.loads(base64.b64decode(ck_base64))
    print("\033[96mCKD Response ✓\033[0m")
    return ck
