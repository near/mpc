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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::{Bls12381G1PublicKey, CKDAppPublicKey, CKDRequest};
    use near_account_id::AccountId;

    #[test]
    fn ckd_request_new__should_derives_app_id_deterministically() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let pk = CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([1u8; 48]));
        let domain_id = DomainId(0);

        let r1 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        let r2 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        assert_eq!(r1.app_id, r2.app_id);

        let r3 = CKDRequest::new(pk, domain_id, &account_id, "path/b");
        assert_ne!(r1.app_id, r3.app_id);
    }
}
