import pathlib
import sys
import json
import base64
import base58
import os
from cryptography.hazmat.primitives.asymmetric import ec
from blspy import AugSchemeMPL, PrivateKey, G1Element

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
    def b58encode(pk):
        pk_bytes = bytes(pk)
        return "bls12381g1:" + base58.b58encode(pk_bytes).decode("ascii")

    private_key: PrivateKey = AugSchemeMPL.key_gen(os.urandom(32))
    public_key: G1Element = private_key.get_g1()
    pk = b58encode(public_key)
    return pk


def generate_ckd_args(domain: Domain, app_public_key: Optional[str] = None) -> dict:
    assert domain.scheme == "Bls12381"
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
