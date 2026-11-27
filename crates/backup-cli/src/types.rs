use ed25519_dalek::SigningKey;
use mpc_node::config::AesKey128;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentSecrets {
    /// Ed25519 private key used for encrypting P2P communication with MPC nodes
    pub p2p_private_key: SigningKey,
    /// Ed25519 private key used for signing NEAR transactions
    pub near_signer_key: SigningKey,
    /// AES-128 key for encrypting locally stored keyshares
    pub local_storage_aes_key: AesKey128,
}

impl PersistentSecrets {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let p2p_private_key = SigningKey::generate(rng);
        let near_signer_key = SigningKey::generate(rng);
        let local_storage_aes_key = AesKey128::generate(rng);
        Self {
            p2p_private_key,
            near_signer_key,
            local_storage_aes_key,
        }
    }
}
