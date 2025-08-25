use near_sdk::{near, AccountId};

use crate::primitives::domain::DomainId;

#[derive(Clone, Debug)]
#[near(serializers=[json])]
pub struct CKDRequestArgs {
    pub app_public_key: near_sdk::PublicKey,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct CKDRequest {
    /// The app ephemeral public key
    pub app_public_key: near_sdk::PublicKey,
    pub app_id: AccountId,
}

impl CKDRequest {
    pub fn new(app_public_key: near_sdk::PublicKey, app_id: AccountId) -> Self {
        Self {
            app_public_key,
            app_id,
        }
    }
}
