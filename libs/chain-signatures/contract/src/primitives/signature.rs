use crate::crypto_shared;

use crypto_shared::derive_epsilon;
use near_sdk::{near, AccountId, CryptoHash};

use super::domain::DomainId;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct Epsilon([u8; 32]);

impl Epsilon {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct PayloadHash([u8; 32]);

impl PayloadHash {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct SignatureRequest {
    pub epsilon: Epsilon,
    pub payload_hash: PayloadHash,
    pub domain: DomainId,
}

impl SignatureRequest {
    pub fn new(
        domain: DomainId,
        payload_hash: PayloadHash,
        predecessor_id: &AccountId,
        path: &str,
    ) -> Self {
        let epsilon = derive_epsilon(predecessor_id, path);
        SignatureRequest {
            domain,
            epsilon,
            payload_hash,
        }
    }
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh, json])]
pub struct SignRequest {
    pub payload: PayloadHash,
    pub path: String,
    pub key_version: u32,
    pub domain_id: Option<DomainId>,
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
