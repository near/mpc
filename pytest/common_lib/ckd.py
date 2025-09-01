import pathlib
import sys
import json
import base64

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


def generate_app_public_key() -> str:
    return "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd"


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
