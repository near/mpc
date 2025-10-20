use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
pub struct KeyShares {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentSecrets {
    pub p2p_private_key: SigningKey,
    pub near_signer_key: SigningKey,
}

impl PersistentSecrets {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let p2p_private_key = SigningKey::generate(rng);
        let near_signer_key = SigningKey::generate(rng);
        Self {
            p2p_private_key,
            near_signer_key,
        }
    }
}
