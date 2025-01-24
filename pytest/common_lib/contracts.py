from utils import load_binary_file

from borsh_construct import Vec, U8, CStruct, U64, Option, U32
from . import constants


def load_mpc_contract_v0() -> bytearray:
    """
    returns v0 contract
    """
    path = constants.mpc_repo_dir / 'libs/chain-signatures/compiled-contracts/v0.wasm'
    return load_binary_file(path)


def load_mpc_contract_v1() -> bytearray:
    path = constants.mpc_repo_dir / 'libs/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)


def load_mpc_contract() -> bytearray:
    """
    this returns the current contract
    """
    #return load_mpc_contract_v0()
    path = constants.mpc_repo_dir / 'libs/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)


"""
config for smart contract. DOES NOT WORK - still getting a serialization error.
use it as :
    contract_v0.ProposeUpdateArgs.build({
        'code': code,
        'config': {
            'protocol': {
                'message_timeout': 6,
                'garbage_timeout': 7,
                'max_concurrent_introduction': 8,
                'max_concurrent_generation': 9,
                'triple': {
                    'min_triples': 10,
                    'max_triples': 100,
                    'generation_timeout': 10000,
                },
                'presignature': {
                    'min_presignatures': 10,
                    'max_presignatures': 100,
                    'generation_timeout': 10000,
                },
                'signature': {
                    'generation_timeout': 1000,
                    'generation_timeout_total': 1000000,
                    'garbage_timeout': 100000000,
                },
            },
        }
    })
"""

TripleConfig = CStruct("min_triples" / U32, "max_triples" / U32,
                       "generation_timeout" / U64)
PresignatureConfig = CStruct(
    "min_presignatures" / U32,
    "max_presignatures" / U32,
    "generation_timeout" / U64,
)
SignatureConfig = CStruct(
    "generation_timeout" / U64,
    "generation_timeout_total" / U64,
    "garbage_timeout" / U64,
)
ProtocolConfig = CStruct(
    "message_timeout" / U64,
    "garbage_timeout" / U64,
    "max_concurrent_introduction" / U32,
    "max_concurrent_generation" / U32,
    "triple" / TripleConfig,
    "presignature" / PresignatureConfig,
    "signature" / SignatureConfig,
)
Config = CStruct("protocol" / ProtocolConfig, )
ProposeUpdateArgs = CStruct("code" / Option(Vec(U8)),
                            "config" / Option(Config))
