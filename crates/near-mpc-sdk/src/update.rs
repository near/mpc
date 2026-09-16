//! Contract updates: participants vote for the [`UpdateHash`] of an [`Update`], and while a
//! governance threshold of them backs that hash, a participant may submit the payload.

pub use near_mpc_contract_interface::types::{Hash256, Update, UpdateHash};
use sha2::{Digest, Sha256};

/// The [`UpdateHash`] participants vote for to make `update` submittable: the SHA-256 of the
/// code bytes, or of the compact JSON encoding of the config.
pub fn hash(update: &Update) -> UpdateHash {
    hash_with(update, |bytes| Sha256::digest(bytes).into())
}

/// [`hash`] with a caller-provided SHA-256, so the contract can hash a submitted payload with
/// its host function instead of in Wasm while sharing the definition of the hashed bytes.
pub fn hash_with(update: &Update, sha256: impl FnOnce(&[u8]) -> [u8; 32]) -> UpdateHash {
    match update {
        Update::Code(code) => UpdateHash::Code(Hash256(sha256(code))),
        Update::Config(config) => {
            // A struct of plain integers has no failing JSON encoding.
            let json = serde_json::to_vec(config).expect("Config always serializes to JSON");
            UpdateHash::Config(Hash256(sha256(&json)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash256, Update, UpdateHash, hash};

    #[test]
    #[expect(non_snake_case)]
    fn hash__should_be_sha256_of_the_code_bytes() {
        // Given
        let update = Update::Code(b"abc".to_vec());

        // When
        let update_hash = hash(&update);

        // Then
        let expected: [u8; 32] =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(update_hash, UpdateHash::Code(Hash256(expected)));
    }
}
