use crate::crypto::PublicKeyExtended;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::{AttemptId, EpochId, domain::DomainId};
use serde::{Deserialize, Serialize};

/// The identification of a specific distributed key, based on which a node would know exactly what
/// keyshare it has corresponds to this distributed key. (A distributed key refers to a specific set
/// of keyshares that nodes have which can be pieced together to form the secret key.)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct KeyForDomain {
    /// Identifies the domain this key is intended for.
    pub domain_id: DomainId,
    /// Identifies the public key. Although technically redundant given that we have the AttemptId,
    /// we keep it here in the contract so that it can be verified against and queried.
    pub key: PublicKeyExtended,
    /// The attempt ID that generated (initially or as a result of resharing) this distributed key.
    /// Nodes may have made multiple attempts to generate the distributed key, and this uniquely
    /// identifies which one should ultimately be used.
    pub attempt: AttemptId,
}

/// Represents a key for every domain in a specific epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Keyset {
    pub epoch_id: EpochId,
    pub domains: Vec<KeyForDomain>,
}

impl Keyset {
    pub fn new(epoch_id: EpochId, domains: Vec<KeyForDomain>) -> Self {
        Keyset { epoch_id, domains }
    }

    pub fn public_key(&self, domain_id: DomainId) -> Option<PublicKeyExtended> {
        self.domains
            .iter()
            .find(|k| k.domain_id == domain_id)
            .map(|k| k.key.clone())
    }

    pub fn get_domain_ids(&self) -> Vec<DomainId> {
        self.domains.iter().map(|domain| domain.domain_id).collect()
    }
}
