use near_sdk::{near, AccountId};

use crate::primitives::domain::DomainId;
use contract_interface::types as dtos;

#[derive(Clone, Debug)]
#[near(serializers=[json])]
pub struct CKDRequestArgs {
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct CKDRequest {
    /// The app ephemeral public key
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub app_id: AccountId,
    pub domain_id: DomainId,
}

impl CKDRequest {
    pub fn new(
        app_public_key: dtos::Bls12381G1PublicKey,
        app_id: AccountId,
        domain_id: DomainId,
    ) -> Self {
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}
