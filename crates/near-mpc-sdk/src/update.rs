//! The hash participants vote for, and the payload it approves.

pub use near_mpc_contract_interface::types::{Hash256, Update, UpdateHash};

#[cfg(all(feature = "non-contract-usage", not(target_arch = "wasm32")))]
use sha2::{Digest, Sha256};

#[cfg(all(feature = "non-contract-usage", not(target_arch = "wasm32")))]
pub fn hash(update: &Update) -> UpdateHash {
    hash_with(update, |bytes| Sha256::digest(bytes).into())
}

/// The hash function must be SHA-256, or the result will not match what the contract computes.
pub fn hash_with(update: &Update, sha256: impl FnOnce(&[u8]) -> [u8; 32]) -> UpdateHash {
    match update {
        Update::Code(code) => UpdateHash::Code(Hash256(sha256(code))),
        Update::Config(config) => {
            let json = serde_json::to_vec(config).expect("Config always serializes to JSON");
            UpdateHash::Config(Hash256(sha256(&json)))
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "non-contract-usage", not(target_arch = "wasm32")))]
mod tests {
    use super::{Hash256, Update, UpdateHash, hash, hash_with};
    use near_mpc_contract_interface::types::Config;
    use sha2::{Digest, Sha256};
    use test_utils::contract_types::dummy_config;

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

    #[test]
    #[expect(non_snake_case)]
    fn hash__should_be_sha256_of_the_config_json() {
        // Given
        let config = dummy_config(1);

        // When
        let update_hash = hash(&Update::Config(config.clone()));

        // Then
        let json = serde_json::to_vec(&config).unwrap();
        assert_eq!(
            update_hash,
            UpdateHash::Config(Hash256(Sha256::digest(json).into()))
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn hash_with__should_hash_the_config_json_and_keep_the_digest() {
        // Given
        let config = dummy_config(1);
        let mut hashed = Vec::new();

        // When
        let update_hash = hash_with(&Update::Config(config.clone()), |bytes| {
            hashed = bytes.to_vec();
            [9u8; 32]
        });

        // Then
        assert_eq!(serde_json::from_slice::<Config>(&hashed).unwrap(), config);
        assert_eq!(update_hash, UpdateHash::Config(Hash256([9u8; 32])));
    }
}
