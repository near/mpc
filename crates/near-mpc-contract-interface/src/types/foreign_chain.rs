// allow deprecation for module, since macro decorators don't work
// when applied directly on struct.
#![expect(deprecated, reason = "ForeignChainConfiguration is being deprecated")]

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::{EmptyBoundedVec, NonEmptyBTreeSet};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

use crate::types::SignatureResponse;
use crate::types::primitives::{AccountId, DomainId};

/// Maximum number of significant data bits a TON Cell may hold.
///
/// See <https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash>.
pub const TON_CELL_MAX_DATA_BITS: u16 = 1023;

/// Maximum number of data bytes in a TON Cell: ⌈1023/8⌉ = 128 bytes, the
/// byte-padded length of a cell holding the maximal [`TON_CELL_MAX_DATA_BITS`].
///
/// See <https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash>.
pub const TON_CELL_MAX_DATA_BYTES: usize = 128;

/// Maximum number of references a TON Cell may hold.
///
/// See <https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash>.
pub const TON_CELL_MAX_REFS: usize = 4;

/// Data bytes of a TON Cell: between 0 and [`TON_CELL_MAX_DATA_BYTES`] bytes (inclusive).
///
/// Holds the cell's data bits packed big-endian into bytes. The exact number of
/// significant bits is carried separately in [`TonLog::body_bit_length`]; the unused
/// low bits of the final byte are zero. A non-byte-aligned cell body is therefore
/// fully representable: `body_bits` carries the padded bytes and `body_bit_length`
/// recovers the true bit length.
pub type TonCellData = EmptyBoundedVec<u8, TON_CELL_MAX_DATA_BYTES>;

/// References of a TON Cell: between 0 and [`TON_CELL_MAX_REFS`] entries (inclusive).
///
/// Each reference is the 32-byte representation hash of the referenced child cell,
/// matching TON's standard cell representation, in which a parent commits to each
/// child by its representation hash (which recursively commits to the child's entire
/// subtree). Bounding each ref to a fixed 32 bytes removes the unbounded-payload
/// (gas-amplification / DoS) vector of carrying arbitrary child-cell bytes.
pub type TonCellRefs = EmptyBoundedVec<Hash256, TON_CELL_MAX_REFS>;

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
/// A TON outbound log message as observed on-chain.
///
/// `body_bits` and `body_bit_length` together describe the message-body cell's data:
/// `body_bits` holds the bits packed into bytes and `body_bit_length` records how many
/// of those bits are significant (`0..=`[`TON_CELL_MAX_DATA_BITS`]). Keeping the bit
/// length explicit is required for the canonical payload to uniquely identify the cell —
/// two cells that share trailing bytes but differ in bit length (e.g. 1015 vs 1023 bits)
/// must not produce the same [`ForeignTxSignPayload::compute_msg_hash`].
///
/// Well-formedness (the invariants checked by [`TonLog::validate`]) is enforced where the
/// cell is parsed from an RPC response, before the log enters a signing payload.
pub struct TonLog {
    pub from_address: TonAddress,
    pub body_bits: TonCellData,
    /// Number of significant data bits in `body_bits`; see the type-level docs.
    pub body_bit_length: u16,
    pub body_refs: TonCellRefs,
}

/// Well-formedness errors for a [`TonLog`] body, reported by [`TonLog::validate`].
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TonLogError {
    /// `body_bit_length` exceeds [`TON_CELL_MAX_DATA_BITS`].
    BitLengthTooLarge { bit_length: u16 },
    /// `body_bits` byte count does not match `body_bit_length` rounded up to whole bytes.
    BitLengthByteMismatch { bit_length: u16, byte_len: usize },
}

impl core::fmt::Display for TonLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BitLengthTooLarge { bit_length } => write!(
                f,
                "TON cell body_bit_length {bit_length} exceeds maximum {TON_CELL_MAX_DATA_BITS}"
            ),
            Self::BitLengthByteMismatch {
                bit_length,
                byte_len,
            } => write!(
                f,
                "TON cell body_bit_length {bit_length} requires {} body bytes but found {byte_len}",
                bit_length.div_ceil(8)
            ),
        }
    }
}

impl std::error::Error for TonLogError {}

impl TonLog {
    /// Checks the body invariants: `body_bit_length <= `[`TON_CELL_MAX_DATA_BITS`] and
    /// `body_bits` holds exactly `⌈body_bit_length / 8⌉` bytes. Callers that build a
    /// `TonLog` from untrusted input (e.g. an RPC-parsed cell) must call this before the
    /// log is hashed into a signing payload.
    pub fn validate(&self) -> Result<(), TonLogError> {
        if self.body_bit_length > TON_CELL_MAX_DATA_BITS {
            return Err(TonLogError::BitLengthTooLarge {
                bit_length: self.body_bit_length,
            });
        }
        let expected_bytes = usize::from(self.body_bit_length.div_ceil(8));
        if self.body_bits.len() != expected_bytes {
            return Err(TonLogError::BitLengthByteMismatch {
                bit_length: self.body_bit_length,
                byte_len: self.body_bits.len(),
            });
        }
        Ok(())
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
#[non_exhaustive]
pub enum TonExtractedValue {
    Log(TonLog),
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
                    body_bits: vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(),
                    body_bit_length: 32,
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

    fn ton_log_with_body(body_bits: Vec<u8>, body_bit_length: u16) -> TonLog {
        TonLog {
            from_address: TonAddress {
                workchain: 0,
                hash: Hash256([0xaa; 32]),
            },
            body_bits: body_bits.try_into().unwrap(),
            body_bit_length,
            body_refs: vec![].try_into().unwrap(),
        }
    }

    #[rstest]
    #[case::empty(vec![], 0)]
    #[case::single_bit(vec![0x80], 1)]
    #[case::byte_aligned(vec![0xde, 0xad], 16)]
    #[case::non_byte_aligned(vec![0xde, 0xa0], 12)]
    #[case::max(vec![0xff; 128], TON_CELL_MAX_DATA_BITS)]
    fn ton_log_validate__should_accept_consistent_body(
        #[case] body_bits: Vec<u8>,
        #[case] body_bit_length: u16,
    ) {
        // Given
        let log = ton_log_with_body(body_bits, body_bit_length);

        // When / Then
        log.validate().unwrap();
    }

    #[test]
    fn ton_log_validate__should_reject_bit_length_above_max() {
        // Given: one bit past the maximum, with a byte buffer that matches that bit count.
        let log = ton_log_with_body(vec![0xff; 128], TON_CELL_MAX_DATA_BITS + 1);

        // When
        let result = log.validate();

        // Then
        assert_eq!(
            result,
            Err(TonLogError::BitLengthTooLarge {
                bit_length: TON_CELL_MAX_DATA_BITS + 1,
            })
        );
    }

    #[rstest]
    #[case::too_few_bytes(vec![0xde], 16)]
    #[case::too_many_bytes(vec![0xde, 0xad], 1)]
    #[case::empty_bytes_nonzero_bits(vec![], 1)]
    fn ton_log_validate__should_reject_byte_bit_mismatch(
        #[case] body_bits: Vec<u8>,
        #[case] body_bit_length: u16,
    ) {
        // Given
        let byte_len = body_bits.len();
        let log = ton_log_with_body(body_bits, body_bit_length);

        // When
        let result = log.validate();

        // Then
        assert_eq!(
            result,
            Err(TonLogError::BitLengthByteMismatch {
                bit_length: body_bit_length,
                byte_len,
            })
        );
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
                values: vec![ExtractedValue::TonExtractedValue(TonExtractedValue::Log(
                    ton_log_with_body(vec![0xff], body_bit_length),
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
