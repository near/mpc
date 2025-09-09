import json

from utils import load_binary_file
from enum import Enum
from borsh_construct import Vec, U8, CStruct, U64, Option, Enum, String
from .constants import MPC_REPO_DIR

COMPILED_CONTRACT_PATH = (
    MPC_REPO_DIR / "libs" / "chain-signatures" / "res" / "mpc_contract.wasm"
)
MIGRATE_CURRENT_CONTRACT_PATH = (
    MPC_REPO_DIR
    / "pytest"
    / "tests"
    / "test_contracts"
    / "migration"
    / "res"
    / "migration_contract.wasm"
)
PARALLEL_CONTRACT_PATH = (
    MPC_REPO_DIR
    / "pytest"
    / "tests"
    / "test_contracts"
    / "parallel"
    / "res"
    / "contract.wasm"
)

TESTNET_ACCOUNT_ID = "v1.signer-prod.testnet"
MAINNET_ACCOUNT_ID = "v1.signer"


def build_view_code_request(account_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "query",
        "params": {
            "request_type": "view_code",
            "finality": "final",
            "account_id": account_id,
        },
    }


def load_mpc_contract() -> bytearray:
    """
    Returns the current contract.
    """
    return load_binary_file(COMPILED_CONTRACT_PATH)


class ConfigV2:
    def __init__(self, max_num_requests_to_remove, request_timeout_blocks):
        self.max_num_requests_to_remove = max_num_requests_to_remove
        self.request_timeout_blocks = request_timeout_blocks

    def dump_json(self):
        return json.dumps(
            {
                "request_timeout_blocks": self.max_num_requests_to_remove,
                "key_event_timeout_blocks": self.request_timeout_blocks,
            }
        )

    def get(self):
        return {
            "max_num_requests_to_remove": self.max_num_requests_to_remove,
            "request_timeout_blocks": self.request_timeout_blocks,
        }


ConfigV2Borsh = CStruct("key_event_timeout_blocks" / U64)
ProposeUpdateArgsV2 = CStruct(
    "code" / Option(Vec(U8)), "config" / Option(ConfigV2Borsh)
)


class UpdateArgsV2:
    def __init__(self, code_path=None, config=None):
        self.code_path = code_path
        self.config = config
        self._code = None

    def borsh_serialize(self):
        return ProposeUpdateArgsV2.build(
            {
                "code": self.code(),
                "config": self.config.get() if self.config is not None else None,
            }
        )

    def code(self):
        if self.code_path is None:
            return None
        if self._code is None:
            self._code = load_binary_file(self.code_path)
        return self._code

    def dump_json(self):
        assert self.config is not None
        return self.config.dump_json()


class ContractMethod(str, Enum):
    VOTE_NEW_PARAMETERS = "vote_new_parameters"
    VOTE_ADD_DOMAINS = "vote_add_domains"
    PROPOSE_UPDATE = "propose_update"
    VOTE_UPDATE = "vote_update"


# Borsh serialization for submit_participant_info
# The contract expects tuple: (Attestation, PublicKey)
# Let's try the simplest possible approach first

class SubmitParticipantInfoArgsV2:
    def __init__(self, attestation_data="Valid", tls_public_key=None):
        self.attestation_data = attestation_data  # "Valid", "Invalid"
        self.tls_public_key = tls_public_key or "ed25519:5vJZzE2vQFqKf2vDfnZf5bYqBrPhZgLM4W1DftFWaK1i"

    def borsh_serialize(self):
        # Based on args_borsh((attestation.clone(), tls_key.clone()))
        # Serialize as tuple of (Attestation, PublicKey)
        
        import struct
        import base58
        
        # 1. Attestation::Mock(MockAttestation::Valid)
        # Outer enum: Mock = 0 (u8), Inner enum: Valid = 0 (u8)  
        attestation_bytes = struct.pack('<BB', 0, 0)  # Little-endian: Mock(0), Valid(0)
        
        # 2. PublicKey - Parse "ed25519:base58key" format 
        # According to NEAR PublicKey Borsh format:
        # - ED25519: 0u8 (key type) + 32 bytes of key data
        # - SECP256K1: 1u8 (key type) + 64 bytes of key data
        
        if self.tls_public_key.startswith("ed25519:"):
            # Extract base58 part and decode
            base58_key = self.tls_public_key[8:]  # Remove "ed25519:" prefix
            key_data = base58.b58decode(base58_key)  # Should be 32 bytes
            
            if len(key_data) != 32:
                raise ValueError(f"ED25519 key must be 32 bytes, got {len(key_data)}")
            
            # PublicKey::ED25519: 0u8 + 32 bytes
            public_key_bytes = struct.pack('<B', 0) + key_data
            
        elif self.tls_public_key.startswith("secp256k1:"):
            # Extract base58 part and decode
            base58_key = self.tls_public_key[10:]  # Remove "secp256k1:" prefix
            key_data = base58.b58decode(base58_key)  # Should be 64 bytes
            
            if len(key_data) != 64:
                raise ValueError(f"SECP256K1 key must be 64 bytes, got {len(key_data)}")
            
            # PublicKey::SECP256K1: 1u8 + 64 bytes
            public_key_bytes = struct.pack('<B', 1) + key_data
        else:
            raise ValueError(f"Unsupported public key format: {self.tls_public_key}")
        
        return attestation_bytes + public_key_bytes
