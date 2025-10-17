use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
pub struct KeyShares {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistentSecrets {
    pub p2p_private_key: SigningKey,
    pub near_signer_key: SigningKey,
}
