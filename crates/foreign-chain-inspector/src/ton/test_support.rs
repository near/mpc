//! Fixtures shared by the TON unit tests.
//!
//! The golden BoC vectors were captured from `tonlib_core` 0.26.11 before it
//! was removed: base64 BoC, the root cell's representation hash, and any child
//! hashes.

use near_mpc_contract_interface::types::TonCellBody;

/// An empty cell (0 bits, no references).
pub(crate) const EMPTY: &str = "te6ccgEBAQEAAgAAAA==";
pub(crate) const EMPTY_HASH: &str =
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7";
/// A byte-aligned 4-byte cell `0x99000001` (32 bits), no references.
pub(crate) const BYTE_ALIGNED: &str = "te6ccgEBAQEABgAACJkAAAE=";
pub(crate) const BYTE_ALIGNED_HASH: &str =
    "62a994bfc5f15d5bd325e6390812a0dfc7c8fdef24a39135a34e558d9885257f";
/// A non-byte-aligned cell `0xdea0` (12 bits).
pub(crate) const NON_BYTE_ALIGNED: &str = "te6ccgEBAQEABAAAA96o";
/// A 2-byte cell `0xdead` (16 bits) referencing one child cell `0xaa` (8 bits).
pub(crate) const ONE_REF: &str = "te6ccgEBAgEACAABBN6tAQACqg==";
/// The representation hash of [`ONE_REF`]'s child cell.
pub(crate) const ONE_REF_CHILD_HASH: &str =
    "08da99aa8eb36c5c627a221005ca60f004f392de79b18e90be10c0cb420ab332";
/// A cell chain `0xfe`/7 bits -> `0x99`/8 bits -> `0x42`/8 bits.
pub(crate) const NESTED: &str = "te6ccgEBAwEACwABAf8BAQKZAgACQg==";
/// The representation hash of [`NESTED`]'s direct child.
pub(crate) const NESTED_CHILD_HASH: &str =
    "23ae53d421a4cc4a2f249bd082bb0c6a774deb7974832993b813d6b6553e89f1";

pub(crate) fn cell_body(bits: Vec<u8>, bit_length: u16) -> TonCellBody {
    TonCellBody::new(bits.try_into().unwrap(), bit_length).unwrap()
}
