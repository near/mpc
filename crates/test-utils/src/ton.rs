//! Fixtures and constructors for TON inspector tests.
//!
//! The golden BoC vectors were captured from `tonlib_core` 0.26.11 before it
//! was removed: base64 BoC, the root cell's representation hash, and any child
//! hashes.

use near_mpc_contract_interface::types::TonCellBody;

/// Generic BoC magic prefix (`serialized_boc#b5ee9c72`).
const GENERIC_BOC_MAGIC: u32 = 0xb5ee_9c72;

/// An empty cell (0 bits, no references).
pub const EMPTY: &str = "te6ccgEBAQEAAgAAAA==";
pub const EMPTY_HASH: &str = "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7";
/// A byte-aligned 4-byte cell `0x99000001` (32 bits), no references.
pub const BYTE_ALIGNED: &str = "te6ccgEBAQEABgAACJkAAAE=";
pub const BYTE_ALIGNED_HASH: &str =
    "62a994bfc5f15d5bd325e6390812a0dfc7c8fdef24a39135a34e558d9885257f";
/// A non-byte-aligned cell `0xdea0` (12 bits).
pub const NON_BYTE_ALIGNED: &str = "te6ccgEBAQEABAAAA96o";
/// A 2-byte cell `0xdead` (16 bits) referencing one child cell `0xaa` (8 bits).
pub const ONE_REF: &str = "te6ccgEBAgEACAABBN6tAQACqg==";
/// The representation hash of [`ONE_REF`]'s child cell.
pub const ONE_REF_CHILD_HASH: &str =
    "08da99aa8eb36c5c627a221005ca60f004f392de79b18e90be10c0cb420ab332";
/// A cell chain `0xfe`/7 bits -> `0x99`/8 bits -> `0x42`/8 bits.
pub const NESTED: &str = "te6ccgEBAwEACwABAf8BAQKZAgACQg==";
/// The representation hash of [`NESTED`]'s direct child.
pub const NESTED_CHILD_HASH: &str =
    "23ae53d421a4cc4a2f249bd082bb0c6a774deb7974832993b813d6b6553e89f1";

pub fn cell_body(bits: Vec<u8>, bit_length: u16) -> TonCellBody {
    TonCellBody::new(bits.try_into().unwrap(), bit_length).unwrap()
}

pub fn hash32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes")
}

/// Serialize one ref-less leaf cell as a generic base64 BoC, matching the
/// `body` field the TON HTTP API v3 emits for a message's `message_content`.
/// The golden test below pins it against tonlib's output.
pub fn encode_single_leaf_boc(data: &[u8], bit_len: u16) -> String {
    let full_bytes = usize::from(bit_len / 8);
    let rem = bit_len % 8;
    let mut cell_data = data.to_vec();
    let d2 = if rem == 0 {
        2 * full_bytes
    } else {
        *cell_data.last_mut().expect("rem != 0 implies a final byte") |= 0x80u8 >> rem;
        2 * full_bytes + 1
    } as u8;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&GENERIC_BOC_MAGIC.to_be_bytes());
    bytes.extend_from_slice(&[
        0x01,                        // flags: no idx/crc/cache, ref_size = 1
        0x01,                        // off_size = 1
        0x01,                        // cell count
        0x01,                        // root count
        0x00,                        // absent
        (2 + cell_data.len()) as u8, // total cell-data size
        0x00,                        // root index
        0x00,                        // d1: no refs, ordinary, level 0
        d2,
    ]);
    bytes.extend_from_slice(&cell_data);

    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_leaf_boc__should_match_tonlib_serialization() {
        assert_eq!(encode_single_leaf_boc(&[], 0), EMPTY);
        assert_eq!(
            encode_single_leaf_boc(&[0x99, 0x00, 0x00, 0x01], 32),
            BYTE_ALIGNED
        );
        assert_eq!(encode_single_leaf_boc(&[0xde, 0xa0], 12), NON_BYTE_ALIGNED);
    }
}
