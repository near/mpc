//! Additive-rerandomization variant of the robust ECDSA scheme.
//!
//! Unlike the multiplicative rerandomization of the parent module, this
//! variant keeps `w = a * k` secret during presigning and defers the
//! \[BB89\] nonce inversion to the signing phase, so the presignature can be
//! rerandomized additively (`k + delta`) as analyzed in
//! \[GS21\] <https://eprint.iacr.org/2021/1330.pdf> and deployed in
//! \[GS22\] <https://eprint.iacr.org/2022/506>.
//! See `docs/ecdsa/robust_ecdsa/signing.md` for the protocol specification and
//! `docs/ecdsa/robust_ecdsa/additive-security.md` for the security analysis.
//!
//! *** Warning ***
//! A presignature must never be consumed by both this variant and the parent
//! one: the parent presigning publishes `w`, and opening `mu = w + delta * a`
//! for the same presignature would then reveal the nonce (and hence the key).

pub mod presign;
pub mod sign;

#[cfg(test)]
#[expect(non_snake_case)]
mod test;

pub use presign::{AdditivePresignOutput, AdditiveRerandomizedPresignOutput};
