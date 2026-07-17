// allow deprecation for module, since macro decorators don't work
// when applied directly on struct.
#![expect(deprecated, reason = "ForeignChainConfiguration is being deprecated")]

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet, UpperBoundedVec};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

use crate::types::primitives::{AccountId, DomainId};
use crate::types::{Ed25519PublicKey, SignatureResponse};

/// Maximum number of significant data bits a TON Cell may hold.
///
/// See <https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash>.
pub const TON_CELL_MAX_DATA_BITS: u16 = 1023;

/// Maximum number of data bytes in a TON Cell: ⌈1023/8⌉ = 128 bytes, the
/// byte-padded length of a cell holding the maximal [`TON_CELL_MAX_DATA_BITS`].
///
/// See <https://docs.ton.org/blockchain-basics/primitives/serialization/cells#basic-structure>.
pub const TON_CELL_MAX_DATA_BYTES: usize = 128;

/// Maximum number of references a TON Cell may hold.
///
/// See <https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash>.
pub const TON_CELL_MAX_REFS: usize = 4;

/// Data bytes of a TON Cell: between 0 and [`TON_CELL_MAX_DATA_BYTES`] bytes (inclusive).
///
/// Holds a cell's data bits packed big-endian into bytes; the exact significant bit count
/// is carried alongside it in [`TonCellBody`].
pub type TonCellData = UpperBoundedVec<u8, TON_CELL_MAX_DATA_BYTES>;

/// References of a TON Cell: between 0 and [`TON_CELL_MAX_REFS`] entries (inclusive).
pub type TonCellRefs = UpperBoundedVec<Hash256, TON_CELL_MAX_REFS>;

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
/// Serialized as a `u8` discriminant via `serde_repr` and `#[borsh(use_discriminant = true)]`.
/// The `JsonSchema` impl below delegates to `u8` because schemars doesn't understand `serde_repr`.
/// The schema and serialization need to be kept in sync so that our ABI snapshot test captures
/// breaking changes.
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum ForeignTxPayloadVersion {
    V1 = 1,
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for ForeignTxPayloadVersion {
    fn schema_name() -> String {
        u8::schema_name()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        u8::json_schema(generator)
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionRequestArgs {
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    pub payload_version: ForeignTxPayloadVersion,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionRequest {
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    pub payload_version: ForeignTxPayloadVersion,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionResponse {
    pub payload_hash: Hash256,
    pub signature: SignatureResponse,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ForeignChainRpcRequest {
    Abstract(EvmRpcRequest),
    Ethereum(EvmRpcRequest),
    Solana(SolanaRpcRequest),
    Bitcoin(BitcoinRpcRequest),
    Starknet(StarknetRpcRequest),
    Bnb(EvmRpcRequest),
    Base(EvmRpcRequest),
    Arbitrum(EvmRpcRequest),
    Polygon(EvmRpcRequest),
    HyperEvm(EvmRpcRequest),
    Ton(TonRpcRequest),
    Aptos(AptosRpcRequest),
    Sui(SuiRpcRequest),
}

impl ForeignChainRpcRequest {
    pub fn chain(&self) -> ForeignChain {
        match self {
            Self::Abstract(_) => ForeignChain::Abstract,
            Self::Ethereum(_) => ForeignChain::Ethereum,
            Self::Solana(_) => ForeignChain::Solana,
            Self::Bitcoin(_) => ForeignChain::Bitcoin,
            Self::Starknet(_) => ForeignChain::Starknet,
            Self::Bnb(_) => ForeignChain::Bnb,
            Self::Base(_) => ForeignChain::Base,
            Self::Arbitrum(_) => ForeignChain::Arbitrum,
            Self::Polygon(_) => ForeignChain::Polygon,
            Self::HyperEvm(_) => ForeignChain::HyperEvm,
            Self::Ton(_) => ForeignChain::Ton,
            Self::Aptos(_) => ForeignChain::Aptos,
            Self::Sui(_) => ForeignChain::Sui,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct EvmRpcRequest {
    pub tx_id: EvmTxId,
    pub extractors: Vec<EvmExtractor>,
    pub finality: EvmFinality,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SolanaRpcRequest {
    pub tx_id: SolanaTxId,
    pub finality: SolanaFinality,
    pub extractors: Vec<SolanaExtractor>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct BitcoinRpcRequest {
    pub tx_id: BitcoinTxId,
    pub confirmations: BlockConfirmations,
    pub extractors: Vec<BitcoinExtractor>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct TonRpcRequest {
    pub tx_id: TonTxId,
    pub account: TonAddress,
    pub finality: TonFinality,
    pub extractors: Vec<TonExtractor>,
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct TonTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct TonAddress {
    pub workchain: i32,
    pub hash: Hash256,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum TonFinality {
    MasterchainIncluded,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum TonExtractor {
    Log { message_index: u64 } = 1,
}

/// The data section of a TON message-body cell.
///
/// A TON cell carries up to [`TON_CELL_MAX_DATA_BITS`] *bits*, which need not be a whole
/// number of bytes, so we store the bits packed big-endian into bytes ([`TonCellData`],
/// the final byte's unused low bits zeroed) alongside the exact significant bit count.
/// The bit length is kept explicit so two cells that share trailing bytes but differ in
/// bit length (e.g. 1015 vs 1023 bits) do not collide under
/// [`ForeignTxSignPayload::compute_msg_hash`].
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, BorshSerialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct TonCellBody {
    bytes: TonCellData,
    bit_length: u16,
}

impl TonCellBody {
    /// Builds a cell body from `bits` (significant bits packed big-endian into bytes) and
    /// the significant `bit_length`, enforcing `bit_length <= `[`TON_CELL_MAX_DATA_BITS`],
    /// `bits.len() == ⌈bit_length / 8⌉`, and that the final byte's unused low bits (the
    /// `8 * bits.len() - bit_length` bits beyond `bit_length`) are zero, so that the byte
    /// representation is canonical for a given `bit_length`.
    pub fn new(bytes: TonCellData, bit_length: u16) -> Result<Self, TonCellBodyError> {
        if bit_length > TON_CELL_MAX_DATA_BITS {
            return Err(TonCellBodyError::BitLengthTooLarge { bit_length });
        }
        let expected_bytes = usize::from(bit_length.div_ceil(8));
        if bytes.len() != expected_bytes {
            return Err(TonCellBodyError::BitLengthByteMismatch {
                bit_length,
                byte_len: bytes.len(),
            });
        }
        // When `bit_length` is not byte-aligned, the final byte's low `unused_bits` bits lie
        // beyond the significant data and must be zero. Otherwise two bodies sharing a
        // `bit_length` but differing in padding would be distinct under `Eq`/`Hash` and
        // hash differently under `compute_msg_hash`, despite encoding the same cell.
        let unused_bits = (8 - (bit_length % 8)) % 8;
        if unused_bits != 0 {
            let last_byte = *bytes
                .last()
                .expect("non-zero bit_length implies a final byte");
            let padding_mask = (1u8 << unused_bits) - 1;
            if last_byte & padding_mask != 0 {
                return Err(TonCellBodyError::TrailingBitsNotZero {
                    bit_length,
                    last_byte,
                });
            }
        }
        Ok(Self { bytes, bit_length })
    }
}

/// Wire representation shared by the `Deserialize` and `BorshDeserialize` impls, so the
/// field layout and the routing through [`TonCellBody::new`] live in one place.
#[derive(Deserialize, BorshDeserialize)]
struct TonCellBodyRepr {
    cell_data: TonCellData,
    bit_length: u16,
}

impl TryFrom<TonCellBodyRepr> for TonCellBody {
    type Error = TonCellBodyError;

    fn try_from(repr: TonCellBodyRepr) -> Result<Self, Self::Error> {
        Self::new(repr.cell_data, repr.bit_length)
    }
}

impl<'de> Deserialize<'de> for TonCellBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <TonCellBodyRepr as Deserialize>::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl BorshDeserialize for TonCellBody {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        TonCellBodyRepr::deserialize_reader(reader)?
            .try_into()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

/// Errors building a [`TonCellBody`]; see [`TonCellBody::new`].
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TonCellBodyError {
    /// `bit_length` exceeds [`TON_CELL_MAX_DATA_BITS`].
    BitLengthTooLarge { bit_length: u16 },
    /// The byte count does not match `bit_length` rounded up to whole bytes.
    BitLengthByteMismatch { bit_length: u16, byte_len: usize },
    /// The final byte's unused low bits (beyond `bit_length`) are not zero.
    TrailingBitsNotZero { bit_length: u16, last_byte: u8 },
}

impl core::fmt::Display for TonCellBodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BitLengthTooLarge { bit_length } => write!(
                f,
                "TON cell bit_length {bit_length} exceeds maximum {TON_CELL_MAX_DATA_BITS}"
            ),
            Self::BitLengthByteMismatch {
                bit_length,
                byte_len,
            } => write!(
                f,
                "TON cell bit_length {bit_length} requires {} body bytes but found {byte_len}",
                bit_length.div_ceil(8)
            ),
            Self::TrailingBitsNotZero {
                bit_length,
                last_byte,
            } => write!(
                f,
                "TON cell with bit_length {bit_length} has non-zero unused padding bits in final byte {last_byte:#04x}"
            ),
        }
    }
}

impl std::error::Error for TonCellBodyError {}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
/// A TON outbound log message as observed on-chain. The message body is a
/// [`TonCellBody`], which is well-formed by construction.
pub struct TonLog {
    pub from_address: TonAddress,
    pub body: TonCellBody,
    pub body_refs: TonCellRefs,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum TonExtractedValue {
    Log(TonLog),
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AptosTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AptosAddress(#[serde_as(as = "Hex")] pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AptosRpcRequest {
    pub tx_id: AptosTxId,
    pub finality: AptosFinality,
    pub extractors: Vec<AptosExtractor>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum AptosFinality {
    Committed,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum AptosExtractor {
    Event { event_index: u64 } = 1,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AptosEvent {
    pub account_address: AptosAddress,
    pub sequence_number: u64,
    pub type_tag: String,
    pub data: String,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum AptosExtractedValue {
    Event(AptosEvent),
}

/// 32-byte Sui transaction digest (Blake2b-256 of the signed transaction data).
/// Sui APIs display it base58-encoded; here it is carried as raw bytes (hex in JSON).
#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiAddress(#[serde_as(as = "Hex")] pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiRpcRequest {
    pub tx_id: SuiTxId,
    pub finality: SuiFinality,
    pub extractors: Vec<SuiExtractor>,
}

/// Sui has no reorgs; a transaction is final once it is included in a
/// committee-certified checkpoint.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SuiFinality {
    Checkpointed,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum SuiExtractor {
    Event { event_index: u64 } = 1,
}

/// A Sui Move event as observed on-chain.
///
/// `type_tag` carries every address in canonical long form (`0x` + 64 lowercase hex),
/// and `bcs` carries the BCS-serialized event contents. Both are provider-independent,
/// unlike the API's `parsedJson` rendering, which may vary across node versions.
#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiEvent {
    pub package_id: SuiAddress,
    pub transaction_module: String,
    pub sender: SuiAddress,
    pub type_tag: String,
    #[serde_as(as = "Hex")]
    pub bcs: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SuiExtractedValue {
    Event(SuiEvent),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct StarknetRpcRequest {
    pub tx_id: StarknetTxId,
    pub finality: StarknetFinality,
    pub extractors: Vec<StarknetExtractor>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum EvmFinality {
    Latest,
    Safe,
    Finalized,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SolanaFinality {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum StarknetFinality {
    AcceptedOnL2,
    AcceptedOnL1,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum EvmExtractor {
    BlockHash = 0,
    Log { log_index: u64 } = 1,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct EvmLog {
    pub removed: bool,
    pub log_index: u64,
    pub transaction_index: u64,
    pub transaction_hash: Hash256,
    pub block_hash: Hash256,
    pub block_number: u64,
    pub address: Hash160,
    pub data: String,
    pub topics: Vec<Hash256>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SolanaExtractor {
    SolanaProgramIdIndex { ix_index: u32 },
    SolanaDataHash { ix_index: u32 },
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum BitcoinExtractor {
    BlockHash = 0,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum StarknetExtractor {
    BlockHash = 0,
    Log { log_index: u64 } = 1,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct StarknetLog {
    pub block_hash: StarknetFelt,
    pub block_number: u64,
    pub data: Vec<StarknetFelt>,
    pub from_address: StarknetFelt,
    pub keys: Vec<StarknetFelt>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ExtractedValue {
    BitcoinExtractedValue(BitcoinExtractedValue),
    EvmExtractedValue(EvmExtractedValue),
    StarknetExtractedValue(StarknetExtractedValue),
    TonExtractedValue(TonExtractedValue),
    AptosExtractedValue(AptosExtractedValue),
    SuiExtractedValue(SuiExtractedValue),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum EvmExtractedValue {
    BlockHash(Hash256),
    Log(EvmLog),
}
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum BitcoinExtractedValue {
    BlockHash(Hash256),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum StarknetExtractedValue {
    BlockHash(StarknetFelt),
    Log(StarknetLog),
}

#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ForeignChain {
    Solana,
    Bitcoin,
    Ethereum,
    Base,
    Bnb,
    Arbitrum,
    Abstract,
    Starknet,
    Polygon,
    HyperEvm,
    Ton,
    Aptos,
    Sui,
}

impl ForeignChain {
    /// Stable snake_case identifier for this chain, shared by config keys,
    /// metric labels, and health-check result keys. Exhaustive on purpose
    /// to avoid drift.
    pub fn label(&self) -> &'static str {
        match self {
            ForeignChain::Solana => "solana",
            ForeignChain::Bitcoin => "bitcoin",
            ForeignChain::Ethereum => "ethereum",
            ForeignChain::Base => "base",
            ForeignChain::Bnb => "bnb",
            ForeignChain::Arbitrum => "arbitrum",
            ForeignChain::Abstract => "abstract",
            ForeignChain::Starknet => "starknet",
            ForeignChain::Polygon => "polygon",
            ForeignChain::HyperEvm => "hyper_evm",
            ForeignChain::Ton => "ton",
            ForeignChain::Aptos => "aptos",
            ForeignChain::Sui => "sui",
        }
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[deprecated(note = "https://github.com/near/mpc/issues/3079")]
pub struct ForeignChainConfiguration(BTreeMap<ForeignChain, NonEmptyBTreeSet<RpcProvider>>);

#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SupportedForeignChains(BTreeSet<ForeignChain>);

/// Set of foreign chains a node reports it can serve; aggregated into [`AvailableForeignChains`] by the contract.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ForeignChainsConfig(BTreeSet<ForeignChain>);

/// Per-node foreign-chain configs, keyed by each node's TLS public key.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ForeignChainsConfigs(BTreeMap<Ed25519PublicKey, ForeignChainsConfig>);

/// The set of foreign chains available across the threshold of active participants. Returned by
/// `get_available_foreign_chains`; computed from the per-node [`ForeignChainsConfig`] reports.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AvailableForeignChains(BTreeSet<ForeignChain>);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct RpcProvider {
    pub rpc_url: String,
}

#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
    derive_more::From,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ForeignChainSupportByNode {
    pub foreign_chain_support_by_node: BTreeMap<AccountId, SupportedForeignChains>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct BlockConfirmations(pub u64);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Deref,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Hash256(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Hash160(#[serde_as(as = "Hex")] pub [u8; 20]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct EvmTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SolanaTxId(
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32.
    )]
    #[serde_as(as = "Hex")]
    pub [u8; 64],
);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct BitcoinTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct StarknetFelt(#[serde_as(as = "Hex")] pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct StarknetTxId(pub StarknetFelt);

/// Canonical payload for foreign-chain transaction verification signatures.
///
/// This enum is Borsh-serialized and SHA-256 hashed to produce the 32-byte
/// `msg_hash` that the MPC network signs. Callers select the payload version
/// via `VerifyForeignTransactionRequestArgs::payload_version`.
///
/// IMPORTANT: Never reorder existing enum variants or struct fields, as this
/// would change the Borsh encoding and break signature verification.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum ForeignTxSignPayload {
    V1(ForeignTxSignPayloadV1),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ForeignTxSignPayloadV1 {
    pub request: ForeignChainRpcRequest,
    pub values: Vec<ExtractedValue>,
}

impl ForeignTxSignPayload {
    pub fn compute_msg_hash(&self) -> std::io::Result<Hash256> {
        let mut hasher = sha2::Sha256::new();
        borsh::BorshSerialize::serialize(self, &mut hasher)?;
        Ok(Hash256(hasher.finalize().into()))
    }
}

/// Stable label for an RPC provider entry (e.g. `"alchemy"`, `"ankr"`, `"drpc"`).
/// Unique within a chain in the on-chain foreign-chain RPC whitelist.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProviderId(pub String);

/// Where the operator's API key/token gets injected into the assembled RPC URL.
/// Lives on the contract (not in operator yaml) so the operator can't pick a custom
/// auth shape that lets them inject extra path or query components.
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum AuthScheme {
    /// Token sent in an HTTP header (e.g. `Authorization: Bearer <token>`).
    Header {
        name: String,
        scheme: Option<String>,
    },
    /// Token substituted into a `{placeholder}` in the URL path.
    Path { placeholder: String },
    /// Token sent as a query parameter (`?<name>=<token>`).
    Query { name: String },
    /// Public endpoint, no auth.
    None,
}

/// How chain identity is encoded in the RPC URL. Exactly one of the three encodings,
/// modelled as an enum so a vote can't accidentally produce an "all three" shape.
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ChainRouting {
    /// Chain identity already encoded in `base_url` (subdomain or path prefix).
    /// E.g. Alchemy's `eth-mainnet.g.alchemy.com`, Infura's `mainnet.infura.io`, or
    /// any chain-dedicated endpoint.
    Embedded,
    /// Append `segment` after `base_url`'s path. E.g. Ankr Ethereum: `"eth"`.
    /// `segment` MUST NOT contain `/` (validated when a vote applies).
    PathSegment { segment: String },
    /// Merge a single chain-identifying query param into the URL. E.g. dRPC Ethereum:
    /// `{ name: "network", value: "ethereum" }`.
    /// When `AuthScheme::Query { name: auth_name }` is used, `name` here MUST differ
    /// from `auth_name` (validated when a vote applies).
    QueryParam { name: String, value: String },
}

/// One provider's per-chain configuration, stored as a value in `ChainEntry.providers`
/// (keyed by `ProviderId`). Read by nodes at startup to assemble the actual RPC URL
/// (`base_url` + `chain_routing` + operator-supplied token via `auth_scheme`).
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProviderConfig {
    /// Provider's stable base. When `chain_routing == Embedded`, the chain identifier
    /// is already inside `base_url` (subdomain or path prefix). Otherwise `base_url`
    /// is chain-agnostic and `chain_routing` carries the chain marker.
    pub base_url: String,
    pub auth_scheme: AuthScheme,
    pub chain_routing: ChainRouting,
}

/// Stored state for one chain in the on-chain whitelist: a non-empty map from
/// `ProviderId` to that provider's per-chain configuration, plus the RPC response
/// quorum nodes should use when querying. Returned by the
/// `allowed_foreign_chain_providers` view fn. `NonEmptyBTreeMap` enforces a non-empty
/// provider set and at-most-one entry per `ProviderId` at borsh-deserialize time,
/// and the map iterates in `ProviderId` order — so the canonical hash matches across
/// voters without an explicit sort step.
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ChainEntry {
    pub providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>,
    /// RPC response quorum: when a node queries the providers above, at least this
    /// many must return the same value for the response to be accepted.
    pub quorum: u64,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn foreign_tx_sign_payload_v1_ethereum__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0xab; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),
            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_solana__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Solana(SolanaRpcRequest {
                tx_id: SolanaTxId([0x11; 64]),
                finality: SolanaFinality::Finalized,
                extractors: vec![
                    SolanaExtractor::SolanaProgramIdIndex { ix_index: 0 },
                    SolanaExtractor::SolanaDataHash { ix_index: 1 },
                ],
            }),
            values: vec![
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::BlockHash(Hash256(
                    [0x33; 32],
                ))),
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::BlockHash(Hash256(
                    [0x44; 32],
                ))),
            ],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_bitcoin__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: BitcoinTxId([0x55; 32]),
                confirmations: BlockConfirmations(6),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_starknet__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
                tx_id: StarknetTxId(StarknetFelt([0x77; 32])),
                finality: StarknetFinality::AcceptedOnL1,
                extractors: vec![StarknetExtractor::BlockHash],
            }),
            values: vec![ExtractedValue::StarknetExtractedValue(
                StarknetExtractedValue::BlockHash(StarknetFelt([0x88; 32])),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[rstest]
    #[case::abstract_(
        ForeignChainRpcRequest::Abstract(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Abstract,
    )]
    #[case::ethereum(
        ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Ethereum,
    )]
    #[case::solana(
        ForeignChainRpcRequest::Solana(SolanaRpcRequest {
            tx_id: SolanaTxId([0; 64]),
            finality: SolanaFinality::Finalized,
            extractors: vec![],
        }),
        ForeignChain::Solana,
    )]
    #[case::bitcoin(
        ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0; 32]),
            confirmations: BlockConfirmations(1),
            extractors: vec![],
        }),
        ForeignChain::Bitcoin,
    )]
    #[case::starknet(
        ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
            tx_id: StarknetTxId(StarknetFelt([0; 32])),
            finality: StarknetFinality::AcceptedOnL1,
            extractors: vec![],
        }),
        ForeignChain::Starknet,
    )]
    #[case::bnb(
        ForeignChainRpcRequest::Bnb(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Bnb,
    )]
    #[case::base(
        ForeignChainRpcRequest::Base(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Base,
    )]
    #[case::arbitrum(
        ForeignChainRpcRequest::Arbitrum(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Arbitrum,
    )]
    #[case::hyper_evm(
        ForeignChainRpcRequest::HyperEvm(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::HyperEvm,
    )]
    #[case::polygon(
        ForeignChainRpcRequest::Polygon(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Polygon,
    )]
    #[case::ton(
        ForeignChainRpcRequest::Ton(TonRpcRequest {
            tx_id: TonTxId([0; 32]),
            account: TonAddress {
                workchain: 0,
                hash: Hash256([0; 32]),
            },
            finality: TonFinality::MasterchainIncluded,
            extractors: vec![],
        }),
        ForeignChain::Ton,
    )]
    #[case::aptos(
        ForeignChainRpcRequest::Aptos(AptosRpcRequest {
            tx_id: AptosTxId([0; 32]),
            finality: AptosFinality::Committed,
            extractors: vec![],
        }),
        ForeignChain::Aptos,
    )]
    #[case::sui(
        ForeignChainRpcRequest::Sui(SuiRpcRequest {
            tx_id: SuiTxId([0; 32]),
            finality: SuiFinality::Checkpointed,
            extractors: vec![],
        }),
        ForeignChain::Sui,
    )]
    fn foreign_chain_rpc_request_chain__should_return_correct_chain(
        #[case] request: ForeignChainRpcRequest,
        #[case] expected_chain: ForeignChain,
    ) {
        assert_eq!(request.chain(), expected_chain);
    }

    #[test]
    fn foreign_tx_sign_payload_v1__should_produce_different_hashes_for_different_requests() {
        // Given
        let payload_a = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x01; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),

            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xbb; 32])),
            )],
        });
        let payload_b = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x02; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),
            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xbb; 32])),
            )],
        });

        // When
        let hash_a = payload_a.compute_msg_hash().unwrap();
        let hash_b = payload_b.compute_msg_hash().unwrap();

        // Then
        assert_ne!(hash_a, hash_b);
    }

    #[rstest]
    #[case(ForeignTxPayloadVersion::V1, 1)]
    fn foreign_tx_payload_version__serializes_as_u8(
        #[case] version: ForeignTxPayloadVersion,
        #[case] expected: u8,
    ) {
        assert_eq!(
            serde_json::to_value(version).unwrap(),
            serde_json::json!(expected)
        );
        assert_eq!(borsh::to_vec(&version).unwrap(), vec![expected]);
    }

    #[rstest]
    #[case(1, ForeignTxPayloadVersion::V1)]
    fn foreign_tx_payload_version__deserializes_from_u8(
        #[case] input: u8,
        #[case] expected: ForeignTxPayloadVersion,
    ) {
        let json: ForeignTxPayloadVersion =
            serde_json::from_value(serde_json::json!(input)).unwrap();
        let borsh: ForeignTxPayloadVersion = borsh::from_slice(&[input]).unwrap();
        assert_eq!(json, expected);
        assert_eq!(borsh, expected);
    }

    #[rstest]
    #[case(0)]
    #[case(2)]
    fn foreign_tx_payload_version__rejects_unknown_version(#[case] input: u8) {
        serde_json::from_value::<ForeignTxPayloadVersion>(serde_json::json!(input)).unwrap_err();
        borsh::from_slice::<ForeignTxPayloadVersion>(&[input]).unwrap_err();
    }

    #[test]
    fn foreign_tx_sign_payload_v1_ton__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                tx_id: TonTxId([0x99; 32]),
                account: TonAddress {
                    workchain: 0,
                    hash: Hash256([0xaa; 32]),
                },
                finality: TonFinality::MasterchainIncluded,
                extractors: vec![TonExtractor::Log { message_index: 0 }],
            }),
            values: vec![ExtractedValue::TonExtractedValue(TonExtractedValue::Log(
                TonLog {
                    from_address: TonAddress {
                        workchain: 0,
                        hash: Hash256([0xaa; 32]),
                    },
                    body: TonCellBody::new(vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(), 32)
                        .unwrap(),
                    body_refs: vec![Hash256([0x01; 32]), Hash256([0x02; 32])]
                        .try_into()
                        .unwrap(),
                },
            ))],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_aptos__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Aptos(AptosRpcRequest {
                tx_id: AptosTxId([0xcc; 32]),
                finality: AptosFinality::Committed,
                extractors: vec![AptosExtractor::Event { event_index: 0 }],
            }),
            values: vec![ExtractedValue::AptosExtractedValue(
                AptosExtractedValue::Event(AptosEvent {
                    account_address: AptosAddress([0x00; 32]),
                    sequence_number: 0,
                    type_tag: "0xdeadbeef::omni_bridge::InitTransfer".to_string(),
                    data: "{\"amount\":\"100\"}".to_string(),
                }),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_sui__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Sui(SuiRpcRequest {
                tx_id: SuiTxId([0xdd; 32]),
                finality: SuiFinality::Checkpointed,
                extractors: vec![SuiExtractor::Event { event_index: 0 }],
            }),
            values: vec![ExtractedValue::SuiExtractedValue(SuiExtractedValue::Event(
                SuiEvent {
                    package_id: SuiAddress([0x11; 32]),
                    transaction_module: "omni_bridge".to_string(),
                    sender: SuiAddress([0x22; 32]),
                    type_tag: format!("0x{}::omni_bridge::InitTransfer", "11".repeat(32)),
                    bcs: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ))],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    fn ton_log_with_body(body_bits: Vec<u8>, body_bit_length: u16) -> TonLog {
        TonLog {
            from_address: TonAddress {
                workchain: 0,
                hash: Hash256([0xaa; 32]),
            },
            body: TonCellBody::new(body_bits.try_into().unwrap(), body_bit_length).unwrap(),
            body_refs: vec![].try_into().unwrap(),
        }
    }

    #[rstest]
    #[case::empty(vec![], 0)]
    #[case::single_bit(vec![0x80], 1)]
    #[case::byte_aligned(vec![0xde, 0xad], 16)]
    #[case::non_byte_aligned(vec![0xde, 0xa0], 12)]
    // 1023 bits => final byte's low bit is unused, so it must be zero (0xfe, not 0xff).
    #[case::max([vec![0xff; 127], vec![0xfe]].concat(), TON_CELL_MAX_DATA_BITS)]
    fn ton_cell_body_new__should_accept_consistent_body(
        #[case] bits: Vec<u8>,
        #[case] bit_length: u16,
    ) {
        // Given / When / Then
        TonCellBody::new(bits.try_into().unwrap(), bit_length).unwrap();
    }

    #[test]
    fn ton_cell_body_new__should_reject_bit_length_above_max() {
        // Given: one bit past the maximum, with a byte buffer that matches that bit count.
        // When
        let result = TonCellBody::new(
            vec![0xff; 128].try_into().unwrap(),
            TON_CELL_MAX_DATA_BITS + 1,
        );

        // Then
        assert_eq!(
            result,
            Err(TonCellBodyError::BitLengthTooLarge {
                bit_length: TON_CELL_MAX_DATA_BITS + 1,
            })
        );
    }

    #[rstest]
    #[case::too_few_bytes(vec![0xde], 16)]
    #[case::too_many_bytes(vec![0xde, 0xad], 1)]
    #[case::empty_bytes_nonzero_bits(vec![], 1)]
    fn ton_cell_body_new__should_reject_byte_bit_mismatch(
        #[case] bits: Vec<u8>,
        #[case] bit_length: u16,
    ) {
        // Given
        let byte_len = bits.len();

        // When
        let result = TonCellBody::new(bits.try_into().unwrap(), bit_length);

        // Then
        assert_eq!(
            result,
            Err(TonCellBodyError::BitLengthByteMismatch {
                bit_length,
                byte_len,
            })
        );
    }

    #[rstest]
    // 12 significant bits => final byte's low 4 bits must be zero; 0x01 sets one of them.
    #[case::non_byte_aligned(vec![0xde, 0x01], 12, 0x01)]
    // 1 significant bit => only the top bit is significant; any low bit set is rejected.
    #[case::single_bit(vec![0x01], 1, 0x01)]
    // 1015 bits => final byte's low bit is unused; 0xff sets it.
    #[case::near_max(vec![0xff; 127], 1015, 0xff)]
    fn ton_cell_body_new__should_reject_non_zero_padding_bits(
        #[case] bits: Vec<u8>,
        #[case] bit_length: u16,
        #[case] last_byte: u8,
    ) {
        // When
        let result = TonCellBody::new(bits.try_into().unwrap(), bit_length);

        // Then
        assert_eq!(
            result,
            Err(TonCellBodyError::TrailingBitsNotZero {
                bit_length,
                last_byte,
            })
        );
    }

    #[test]
    fn ton_cell_body_borsh_deserialize__should_reject_inconsistent_body() {
        // Given: borsh bytes for a 1-byte buffer claiming 16 significant bits.
        let bytes = borsh::to_vec(&(vec![0xde_u8], 16_u16)).unwrap();

        // When
        let result = TonCellBody::try_from_slice(&bytes);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn ton_cell_body_json_deserialize__should_reject_inconsistent_body() {
        // Given: JSON for a 1-byte buffer claiming 16 significant bits.
        let json = r#"{"bits":[222],"bit_length":16}"#;

        // When
        let result = serde_json::from_str::<TonCellBody>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn ton_log_compute_msg_hash__should_differ_for_same_bytes_but_different_bit_length() {
        // Given: two cells with identical trailing bytes but different significant bit lengths.
        let make_payload = |body_bit_length: u16| {
            ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
                request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                    tx_id: TonTxId([0x99; 32]),
                    account: TonAddress {
                        workchain: 0,
                        hash: Hash256([0xaa; 32]),
                    },
                    finality: TonFinality::MasterchainIncluded,
                    extractors: vec![TonExtractor::Log { message_index: 0 }],
                }),
                // 0xfe (not 0xff) so the body stays canonical at 7 bits, where the final
                // byte's low bit is unused padding and must be zero.
                values: vec![ExtractedValue::TonExtractedValue(TonExtractedValue::Log(
                    ton_log_with_body(vec![0xfe], body_bit_length),
                ))],
            })
        };

        // When
        let hash_7_bits = make_payload(7).compute_msg_hash().unwrap();
        let hash_8_bits = make_payload(8).compute_msg_hash().unwrap();

        // Then
        assert_ne!(hash_7_bits, hash_8_bits);
    }
}
