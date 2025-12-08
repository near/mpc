use crate::{crypto_shared::kdf::derive_app_id, primitives::domain::DomainId};
use contract_interface::types as dtos;
use near_account_id::AccountId;
use near_sdk::near;

#[derive(Clone, Debug)]
#[near(serializers=[json])]
pub struct CKDRequestArgs {
    pub path: String,
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct CKDRequest {
    /// The app ephemeral public key
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub app_id: dtos::AppId,
    pub domain_id: DomainId,
}

impl CKDRequest {
    pub fn new(
        app_public_key: dtos::Bls12381G1PublicKey,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        path: &str,
    ) -> Self {
        let app_id = derive_app_id(predecessor_id, path);
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}
