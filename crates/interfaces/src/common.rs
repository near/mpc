use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deref, From, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);
