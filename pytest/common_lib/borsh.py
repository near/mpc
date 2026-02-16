"""
Borsh deserializer for VerifyForeignTransactionResponse.

Uses the BinarySerializer from the nearcore pytest library with a schema
matching the Rust contract types.
"""

from serializer import BinarySerializer


def deserialize_verify_foreign_tx_response(data: bytes) -> dict:
    """
    Deserialize a borsh-encoded VerifyForeignTransactionResponse into a dict
    matching the structure previously returned as JSON by the contract.
    """
    ser = BinarySerializer(SCHEMA)
    obj = ser.deserialize(data, VerifyForeignTransactionResponse)
    return _to_dict(obj)


# ---------------------------------------------------------------------------
# Type classes – BinarySerializer instantiates these and sets attributes.
# ---------------------------------------------------------------------------


class VerifyForeignTransactionResponse:
    pass


class ForeignTxSignPayload:
    pass


class ForeignTxSignPayloadV1:
    pass


class ForeignChainRpcRequest:
    pass


class BitcoinRpcRequest:
    pass


class EvmRpcRequest:
    pass


class SolanaRpcRequest:
    pass


class StarknetRpcRequest:
    pass


class BitcoinExtractor:
    pass


class EvmExtractor:
    pass


class EvmExtractorLog:
    pass


class StarknetExtractor:
    pass


class SolanaExtractor:
    pass


class SolanaExtractorProgramIdIndex:
    pass


class SolanaExtractorDataHash:
    pass


class EvmFinality:
    pass


class SolanaFinality:
    pass


class StarknetFinality:
    pass


class ExtractedValue:
    pass


class BitcoinExtractedValue:
    pass


class EvmExtractedValue:
    pass


class StarknetExtractedValue:
    pass


class EvmLog:
    pass


class SignatureResponse:
    pass


class K256Signature:
    pass


class K256AffinePoint:
    pass


class K256Scalar:
    pass


class Ed25519SignatureData:
    pass


# ---------------------------------------------------------------------------
# Borsh schema – mirrors the Rust type definitions.
# ---------------------------------------------------------------------------

SCHEMA = {
    VerifyForeignTransactionResponse: {
        "kind": "struct",
        "fields": [
            ("payload", ForeignTxSignPayload),
            ("signature", SignatureResponse),
        ],
    },
    # -- Payload --
    ForeignTxSignPayload: {
        "kind": "enum",
        "field": "variant",
        "values": [("V1", ForeignTxSignPayloadV1)],
    },
    ForeignTxSignPayloadV1: {
        "kind": "struct",
        "fields": [
            ("request", ForeignChainRpcRequest),
            ("values", [ExtractedValue]),
        ],
    },
    # -- Foreign chain requests --
    ForeignChainRpcRequest: {
        "kind": "enum",
        "field": "variant",
        "values": [
            ("Abstract", EvmRpcRequest),
            ("Ethereum", EvmRpcRequest),
            ("Solana", SolanaRpcRequest),
            ("Bitcoin", BitcoinRpcRequest),
            ("Starknet", StarknetRpcRequest),
        ],
    },
    BitcoinRpcRequest: {
        "kind": "struct",
        "fields": [
            ("tx_id", [32]),
            ("confirmations", "u64"),
            ("extractors", [BitcoinExtractor]),
        ],
    },
    EvmRpcRequest: {
        "kind": "struct",
        "fields": [
            ("tx_id", [32]),
            ("extractors", [EvmExtractor]),
            ("finality", EvmFinality),
        ],
    },
    SolanaRpcRequest: {
        "kind": "struct",
        "fields": [
            ("tx_id", [64]),
            ("finality", SolanaFinality),
            ("extractors", [SolanaExtractor]),
        ],
    },
    StarknetRpcRequest: {
        "kind": "struct",
        "fields": [
            ("tx_id", [32]),
            ("finality", StarknetFinality),
            ("extractors", [StarknetExtractor]),
        ],
    },
    # -- Extractors --
    BitcoinExtractor: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", ())],
    },
    EvmExtractor: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", ()), ("Log", EvmExtractorLog)],
    },
    EvmExtractorLog: {
        "kind": "struct",
        "fields": [("log_index", "u64")],
    },
    StarknetExtractor: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", ())],
    },
    SolanaExtractor: {
        "kind": "enum",
        "field": "variant",
        "values": [
            ("SolanaProgramIdIndex", SolanaExtractorProgramIdIndex),
            ("SolanaDataHash", SolanaExtractorDataHash),
        ],
    },
    SolanaExtractorProgramIdIndex: {
        "kind": "struct",
        "fields": [("ix_index", "u32")],
    },
    SolanaExtractorDataHash: {
        "kind": "struct",
        "fields": [("ix_index", "u32")],
    },
    # -- Finality enums --
    EvmFinality: {
        "kind": "enum",
        "field": "variant",
        "values": [("Latest", ()), ("Safe", ()), ("Finalized", ())],
    },
    SolanaFinality: {
        "kind": "enum",
        "field": "variant",
        "values": [("Processed", ()), ("Confirmed", ()), ("Finalized", ())],
    },
    StarknetFinality: {
        "kind": "enum",
        "field": "variant",
        "values": [("AcceptedOnL2", ()), ("AcceptedOnL1", ())],
    },
    # -- Extracted values --
    ExtractedValue: {
        "kind": "enum",
        "field": "variant",
        "values": [
            ("BitcoinExtractedValue", BitcoinExtractedValue),
            ("EvmExtractedValue", EvmExtractedValue),
            ("StarknetExtractedValue", StarknetExtractedValue),
        ],
    },
    BitcoinExtractedValue: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", [32])],
    },
    EvmExtractedValue: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", [32]), ("Log", EvmLog)],
    },
    StarknetExtractedValue: {
        "kind": "enum",
        "field": "variant",
        "values": [("BlockHash", [32])],
    },
    EvmLog: {
        "kind": "struct",
        "fields": [
            ("removed", "bool"),
            ("log_index", "u64"),
            ("transaction_index", "u64"),
            ("transaction_hash", [32]),
            ("block_hash", [32]),
            ("block_number", "u64"),
            ("address", [20]),
            ("data", "string"),
            ("topics", [[32]]),
        ],
    },
    # -- Signature --
    SignatureResponse: {
        "kind": "enum",
        "field": "variant",
        "values": [
            ("Secp256k1", K256Signature),
            ("Ed25519", Ed25519SignatureData),
        ],
    },
    K256Signature: {
        "kind": "struct",
        "fields": [
            ("big_r", K256AffinePoint),
            ("s", K256Scalar),
            ("recovery_id", "u8"),
        ],
    },
    K256AffinePoint: {
        "kind": "struct",
        "fields": [("affine_point", [33])],
    },
    K256Scalar: {
        "kind": "struct",
        "fields": [("scalar", [32])],
    },
    Ed25519SignatureData: {
        "kind": "struct",
        "fields": [("signature", [64])],
    },
}


# ---------------------------------------------------------------------------
# Object -> dict conversion (matches the previous serde JSON layout).
# ---------------------------------------------------------------------------


def _to_dict(obj):
    """Recursively convert a BinarySerializer-deserialized object to a dict."""
    if obj is None:
        return None
    if isinstance(obj, (int, bool, str)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if isinstance(obj, list):
        return [_to_dict(v) for v in obj]

    schema = SCHEMA.get(type(obj))
    if schema is None:
        return obj

    if schema["kind"] == "struct":
        return {name: _to_dict(getattr(obj, name)) for name, _ in schema["fields"]}

    # Enum
    variant = getattr(obj, schema["field"])
    data = getattr(obj, variant, None)

    if isinstance(obj, SignatureResponse):
        # serde(tag = "scheme") flattens the variant data with a "scheme" key
        result = {"scheme": variant}
        inner = _to_dict(data)
        if isinstance(inner, dict):
            result.update(inner)
        return result

    if data is None:
        # Unit variant (e.g. EvmFinality::Finalized)
        return variant

    return {variant: _to_dict(data)}
