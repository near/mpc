pub mod kdf;
pub mod types;

pub use kdf::{derive_key_secp256k1, derive_tweak};
pub use types::{ed25519_types, k256_types, CKDResponse};

// Our wasm runtime doesn't support good synchronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definitely panic, because they normally expect randomness to be private
#[cfg(target_arch = "wasm32")]
use getrandom::{register_custom_getrandom, Error};
#[cfg(target_arch = "wasm32")]
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);
