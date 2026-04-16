use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Bls12381G1PublicKey, Bls12381G2PublicKey, CkdAppId};
use mpc_primitives::domain::DomainId;

#[derive(
    Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum CKDAppPublicKey {
    AppPublicKey(Bls12381G1PublicKey),
    AppPublicKeyPV(CKDAppPublicKeyPV),
}

impl CKDAppPublicKey {
    pub fn g1_public_key(&self) -> &Bls12381G1PublicKey {
        match self {
            CKDAppPublicKey::AppPublicKey(pk) => pk,
            CKDAppPublicKey::AppPublicKeyPV(pv) => &pv.pk1,
        }
    }
}

impl<'de> Deserialize<'de> for CKDAppPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum Tagged {
            AppPublicKey(Bls12381G1PublicKey),
            AppPublicKeyPV(CKDAppPublicKeyPV),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Tagged(Tagged),
            Plain(Bls12381G1PublicKey),
        }

        match Helper::deserialize(deserializer)? {
            Helper::Tagged(Tagged::AppPublicKey(pk)) => Ok(CKDAppPublicKey::AppPublicKey(pk)),
            Helper::Tagged(Tagged::AppPublicKeyPV(pk)) => Ok(CKDAppPublicKey::AppPublicKeyPV(pk)),
            Helper::Plain(pk) => Ok(CKDAppPublicKey::AppPublicKey(pk)),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct CKDAppPublicKeyPV {
    pub pk1: Bls12381G1PublicKey,
    pub pk2: Bls12381G2PublicKey,
}

/// CKD request with derived app_id.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CKDRequest {
    pub app_public_key: CKDAppPublicKey,
    pub app_id: CkdAppId,
    pub domain_id: DomainId,
}

impl CKDRequest {
    pub fn new(
        app_public_key: CKDAppPublicKey,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        derivation_path: &str,
    ) -> Self {
        let app_id = crate::kdf::derive_app_id(predecessor_id, derivation_path);
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}
