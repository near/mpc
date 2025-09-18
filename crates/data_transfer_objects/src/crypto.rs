use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deref, From, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DtoEd25519PublicKey(pub [u8; 32]);

impl DtoEd25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for DtoEd25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
