pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;

use crate::{
    ecdsa::{AffinePoint, KeygenOutput, RerandomizationArguments, Scalar, Tweak},
    protocol::errors::ProtocolError,
};
use serde::{Deserialize, Serialize};

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput`<Secp256K1Sha256> from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: usize,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
}

impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        tweak: &Tweak,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta = (presignature.beta + presignature.c * tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }

    #[cfg(test)]
    /// Outputs the same elements as in the `PresignatureOutput`
    /// Used for testing the core schemes without rerandomization
    pub fn new_without_rerandomization(presignature: &PresignOutput) -> Self {
        Self {
            big_r: presignature.big_r,
            alpha: presignature.alpha,
            beta: presignature.beta,
            e: presignature.e,
        }
    }
}
