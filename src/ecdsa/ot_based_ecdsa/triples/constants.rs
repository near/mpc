use ecdsa::elliptic_curve::{bigint::Bounded, Curve};
use k256::Secp256k1;

/// The security parameter we use for different constructions
pub const SECURITY_PARAMETER: usize = 128;
/// Field modulus
pub const BITS: usize = <<Secp256k1 as Curve>::Uint as Bounded>::BITS;
