use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_crypto_types::Bls12381G1PublicKey;
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

/// AppId for CKD
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct CkdAppId(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct CKDRequestArgs {
    pub derivation_path: String,
    pub app_public_key: Bls12381G1PublicKey,
    pub domain_id: DomainId,
}
