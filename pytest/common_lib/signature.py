import pathlib
import sys
import random
import json
import base64

from typing import Dict, Literal, Optional

from common_lib.contract_state import Domain, SignatureScheme

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

PayloadType = Literal["Ecdsa", "Eddsa"]

signature_scheme_to_payload: Dict[SignatureScheme, PayloadType] = {
    "Secp256k1": "Ecdsa",
    "Ed25519": "Eddsa",
    "V2Secp256k1": "Ecdsa",
}


def generate_payload(payload_type: PayloadType) -> dict[PayloadType, str]:
    return {payload_type: random.getrandbits(256).to_bytes(32, "big").hex()}


def generate_sign_args(
    domain: Domain, path: str = "test", payload: Optional[dict[PayloadType, str]] = None
) -> dict:
    if payload is None:
        payload = generate_payload(signature_scheme_to_payload[domain.scheme])
    return {
        "request": {
            "domain_id": domain.id,
            "path": path,
            "payload_v2": payload,
        }
    }


def assert_signature_success(res):
    try:
        signature_base64 = res["result"]["status"]["SuccessValue"]
    except KeyError:
        raise AssertionError(json.dumps(res, indent=1))

    signature_base64 += "=" * ((4 - len(signature_base64) % 4) % 4)
    signature = json.loads(base64.b64decode(signature_base64))
    print("\033[96mSign Response ✓\033[0m")
    return signature


def print_signature_outcome(res):
    try:
        signature_base64 = res["result"]["status"]["SuccessValue"]
        signature_base64 += "=" * ((4 - len(signature_base64) % 4) % 4)
        signature = json.loads(base64.b64decode(signature_base64))
        print("\033[96mSign Response ✓\033[0m")
        return signature
    except KeyError:
        print("signature failed")
