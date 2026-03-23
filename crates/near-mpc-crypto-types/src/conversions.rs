#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoConversionError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid affine point bytes")]
    InvalidPoint,
    #[error("invalid scalar bytes")]
    InvalidScalar,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("unsupported curve for this conversion")]
    UnsupportedCurve,
}

#[cfg(feature = "blstrs")]
mod blstrs;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
#[cfg(feature = "k256")]
mod k256;
#[cfg(feature = "near")]
mod near;
