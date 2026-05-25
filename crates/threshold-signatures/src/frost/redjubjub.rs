//! A wrapper for distributed `RedDSA` on `JubJub` curve with only the `Spend Authorization`.
//!
//! Check <https://zips.z.cash/zip-0312> or <https://zips.z.cash/protocol/protocol.pdf#concretespendauthsig>

mod presign;
pub mod sign;
#[cfg(test)]
mod test;

pub use presign::{
    presign, JubjubBlake2b512, KeygenOutput, PresignArguments, PresignOutput, SignatureOption,
};
