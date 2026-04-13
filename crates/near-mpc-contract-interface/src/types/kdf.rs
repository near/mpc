//! Key derivation functions used by both the contract and the node.
//!
//! These are pure hash-based functions with no business logic.

use near_account_id::AccountId;
use sha3::{Digest, Sha3_256};

use super::ckd::CkdAppId;
use super::primitives::Tweak;

/// Constant prefix that ensures tweak derivation values are used specifically for
/// near-mpc-recovery with key derivation protocol vX.Y.Z.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

/// Constant prefix that ensures app_id derivation values are used specifically for
/// near-mpc with derivation protocol vX.Y.Z.
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";

/// Derive a tweak from a predecessor account ID and a derivation path.
pub fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak {
    let hash: [u8; 32] = derive_from_path(TWEAK_DERIVATION_PREFIX, predecessor_id, path);
    Tweak(hash)
}

/// Derive an app ID from a predecessor account ID and a derivation path.
pub fn derive_app_id(predecessor_id: &AccountId, derivation_path: &str) -> CkdAppId {
    let hash: [u8; 32] =
        derive_from_path(APP_ID_DERIVATION_PREFIX, predecessor_id, derivation_path);
    hash.into()
}

fn derive_from_path(derivation_prefix: &str, predecessor_id: &AccountId, path: &str) -> [u8; 32] {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the account id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vulnerable to Hash Malleability/extension attacks.
    let derivation_path = format!("{derivation_prefix}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    hasher.finalize().into()
}
