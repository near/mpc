//! A wrapper for distributed `RedDSA` on `JubJub` curve with only the `Spend Authorization`.
//!
//! Check <https://zips.z.cash/zip-0312> or <https://zips.z.cash/protocol/protocol.pdf#concretespendauthsig>

pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

use reddsa::frost::redjubjub::{
    round1::{SigningCommitments, SigningNonces},
    Identifier, Signature,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// JubJub + Blake2b512 Ciphersuite
pub use reddsa::frost::redjubjub::JubjubBlake2b512;

impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}
impl Ciphersuite for JubjubBlake2b512 {}

pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput,
    /// The threshold for the scheme
    pub threshold: usize,
}

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub nonces: SigningNonces,
    pub commitments_map: BTreeMap<Identifier, SigningCommitments>,
}

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<Signature>;
