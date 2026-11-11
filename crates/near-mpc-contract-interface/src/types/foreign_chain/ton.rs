use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::UpperBoundedVec;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

use super::{Hash256, MAX_EXTRACTORS_PER_REQUEST};

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
    pub extractors: UpperBoundedVec<TonExtractor, MAX_EXTRACTORS_PER_REQUEST>,
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
/// [`ForeignTxSignPayload::compute_msg_hash`](super::ForeignTxSignPayload::compute_msg_hash).
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
/// Wire representation shared by the [`Deserialize`] and [`BorshDeserialize`] impls, so the
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::types::{
        ExtractedValue, ForeignChainRpcRequest, ForeignTxSignPayload, ForeignTxSignPayloadV1,
    };
    use rstest::rstest;

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
                    extractors: [TonExtractor::Log { message_index: 0 }].into(),
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
