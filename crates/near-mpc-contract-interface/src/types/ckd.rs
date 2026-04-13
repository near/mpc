use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use near_mpc_crypto_types::{Bls12381G1PublicKey, Bls12381G2PublicKey};
use serde::{Deserialize, Deserializer, Serialize};

use super::kdf::derive_app_id;
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
    pub app_public_key: CKDAppPublicKey,
    pub domain_id: DomainId,
}

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

/// The response to a CKD request, containing the derived keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct CKDResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}

/// A validated CKD request with the derived app ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let app_id = derive_app_id(predecessor_id, derivation_path);
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use serde_json::json;

    fn dummy_g1() -> Bls12381G1PublicKey {
        Bls12381G1PublicKey([1u8; 48])
    }

    fn dummy_g2() -> Bls12381G2PublicKey {
        Bls12381G2PublicKey([2u8; 96])
    }

    fn g1_string(pk: &Bls12381G1PublicKey) -> String {
        String::from(pk)
    }

    fn g2_string(pk: &Bls12381G2PublicKey) -> String {
        String::from(pk)
    }

    #[test]
    fn deserialize_old_format_plain_g1_key() {
        let pk = dummy_g1();
        let old_json = json!({
            "derivation_path": "test/path",
            "app_public_key": g1_string(&pk),
            "domain_id": 1
        });

        let args: CKDRequestArgs = serde_json::from_value(old_json).unwrap();
        assert_eq!(args.derivation_path, "test/path");
        assert_matches!(args.app_public_key, CKDAppPublicKey::AppPublicKey(key) if key == pk);
        assert_eq!(args.domain_id, DomainId(1));
    }

    #[test]
    fn deserialize_new_format_tagged_app_public_key() {
        let pk = dummy_g1();
        let new_json = json!({
            "derivation_path": "test/path",
            "app_public_key": { "AppPublicKey": g1_string(&pk) },
            "domain_id": 2
        });

        let args: CKDRequestArgs = serde_json::from_value(new_json).unwrap();
        assert_matches!(args.app_public_key, CKDAppPublicKey::AppPublicKey(key) if key == pk);
    }

    #[test]
    fn deserialize_new_format_tagged_app_public_key_pv() {
        let pk1 = dummy_g1();
        let pk2 = dummy_g2();
        let new_json = json!({
            "derivation_path": "test/path",
            "app_public_key": {
                "AppPublicKeyPV": { "pk1": g1_string(&pk1), "pk2": g2_string(&pk2) }
            },
            "domain_id": 3
        });

        let args: CKDRequestArgs = serde_json::from_value(new_json).unwrap();
        assert_matches!(args.app_public_key, CKDAppPublicKey::AppPublicKeyPV(_));
    }

    #[test]
    fn serialize_roundtrip_app_public_key() {
        let pk = dummy_g1();
        let original = CKDAppPublicKey::AppPublicKey(pk.clone());
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: CKDAppPublicKey = serde_json::from_value(serialized).unwrap();
        assert_matches!(deserialized, CKDAppPublicKey::AppPublicKey(key) if key == pk);
    }

    #[test]
    fn serialize_roundtrip_app_public_key_pv() {
        let original = CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
            pk1: dummy_g1(),
            pk2: dummy_g2(),
        });
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: CKDAppPublicKey = serde_json::from_value(serialized).unwrap();
        assert_matches!(deserialized, CKDAppPublicKey::AppPublicKeyPV(_));
    }
}
