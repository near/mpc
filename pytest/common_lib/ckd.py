import pathlib
import sys
import json
import base64
import base58
import os
from blspy import G1Element, G2Element
from py_arkworks_bls12381 import G1Point, G2Point, Scalar
from hashlib import sha3_256

from typing import Optional, Tuple

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib.contract_state import Domain


NEAR_CKD_DOMAIN = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_"
BLS12381G1_PREFIX = "bls12381g1:"
BLS12381G2_PREFIX = "bls12381g2:"


def assert_ckd_success(res):
    try:
        ck_base64 = res["result"]["status"]["SuccessValue"]
    except KeyError:
        raise AssertionError(json.dumps(res, indent=1))

    ck_base64 += "=" * ((4 - len(ck_base64) % 4) % 4)
    ck = json.loads(base64.b64decode(ck_base64))
    print("\033[96mCKD Response ✓\033[0m")
    return ck


def b58encode_g1(pk: G1Point) -> str:
    pk_bytes = bytes(pk.to_compressed_bytes())
    return BLS12381G1_PREFIX + base58.b58encode(pk_bytes).decode("ascii")


def b58encode_g2(pk: G2Point) -> str:
    pk_bytes = bytes(pk.to_compressed_bytes())
    return BLS12381G2_PREFIX + base58.b58encode(pk_bytes).decode("ascii")


def b58decode_g1(pk_encoded: str) -> G1Point:
    assert pk_encoded.startswith(BLS12381G1_PREFIX)
    pk_bytes = base58.b58decode(pk_encoded[len(BLS12381G1_PREFIX) :])
    return G1Point.from_compressed_bytes(pk_bytes)


def b58decode_g2(pk_encoded: str) -> G2Point:
    assert pk_encoded.startswith(BLS12381G2_PREFIX)
    pk_bytes = base58.b58decode(pk_encoded[len(BLS12381G2_PREFIX) :])
    return G2Point.from_compressed_bytes(pk_bytes)


# This function cannot simply return a fixed point because
# some of our tests use concurrent ckd requests, and the indexer
# currently optimizes away identical requests
def generate_app_public_key() -> Tuple[str, Scalar]:
    private_key = Scalar(int.from_bytes(os.urandom(32), "big"))
    public_key: G1Point = G1Point() * private_key
    encoded_pk = b58encode_g1(public_key)
    return encoded_pk, private_key


# These type conversions are only needed because py_arkworks_bls12381 does not support hash_to_curve
# and blspy does not support multiplying a curve point by a scalar (needed for ELGammal decryption)
def verify_bls_signature(
    public_key: G2Point, message: bytes, signature: G1Point
) -> bool:
    pk = G2Element.from_bytes(bytes(public_key.to_compressed_bytes()))
    sig = G1Element.from_bytes(bytes(signature.to_compressed_bytes()))
    # hash_to_curve
    public_key_bytes = bytes(public_key.to_compressed_bytes())
    Hm = G1Element.from_message(public_key_bytes + message, NEAR_CKD_DOMAIN)
    return sig.pair(G2Element.generator()) == Hm.pair(pk)


APP_ID_DERIVATION_PREFIX = "near-mpc v0.1.0 app_id derivation:"


def derive_app_id(account_id: str, path: str) -> bytes:
    return sha3_256(f"{APP_ID_DERIVATION_PREFIX}{account_id},{path}".encode()).digest()


def verify_ckd(
    account_id: str,
    path: str,
    public_key: str,
    app_private_key: Scalar,
    big_y: str,
    big_c: str,
) -> bool:
    public_key = b58decode_g2(public_key)
    big_y = b58decode_g1(big_y)
    big_c = b58decode_g1(big_c)

    app_id = derive_app_id(account_id, path)
    # ElGammal decryption
    k = big_c - big_y * app_private_key
    return verify_bls_signature(public_key, app_id, k)


def generate_ckd_args(
    domain: Domain, app_public_key: Optional[str] = None, path: str = ""
) -> dict:
    assert domain.scheme == "Bls12381"
    if app_public_key is None:
        app_public_key, _ = generate_app_public_key()
    return {
        "request": {
            "derivation_path": path,
            "domain_id": domain.id,
            "app_public_key": app_public_key,
        }
    }
