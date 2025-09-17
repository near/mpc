use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deref, From, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
