use bounded_collections::{BoundedVec, hex_serde};
use contract_interface::types::DomainId;
use serde::{Deserialize, Serialize};

const ECDSA_PAYLOAD_SIZE_BYTES: usize = 32;
const EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES: usize = 32;
const EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES: usize = 1232;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignRequestArgs {
    pub path: String,
    // Either one of the following two must be present.
    #[serde(rename = "payload_v2")]
    pub payload: Payload,
    // Either one of the following two must be present.
    pub domain_id: DomainId,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, derive_more::From,
)]
pub enum Payload {
    Ecdsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES>,
    ),
    Eddsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES>,
    ),
}

#[derive(Debug, Clone)]
struct NotSet;

#[derive(Debug, Clone)]
pub struct SignRequestBuilder<Path, Payload, DomainId> {
    path: Path,
    payload: Payload,
    domain_id: DomainId,
}

impl SignRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn new() -> Self {
        Self {
            path: NotSet,
            payload: NotSet,
            domain_id: NotSet,
        }
    }

    pub fn with_path(self, path: String) -> SignRequestBuilder<String, NotSet, NotSet> {
        SignRequestBuilder {
            path,
            payload: NotSet,
            domain_id: NotSet,
        }
    }
}

impl SignRequestBuilder<String, NotSet, NotSet> {
    pub fn with_payload(
        self,
        payload: impl Into<Payload>,
    ) -> SignRequestBuilder<String, Payload, NotSet> {
        SignRequestBuilder {
            path: self.path,
            payload: payload.into(),
            domain_id: NotSet,
        }
    }
}

impl SignRequestBuilder<String, Payload, NotSet> {
    pub fn with_domain_id(
        self,
        domain_id: impl Into<DomainId>,
    ) -> SignRequestBuilder<String, Payload, DomainId> {
        SignRequestBuilder {
            path: self.path,
            payload: self.payload,
            domain_id: domain_id.into(),
        }
    }
}

impl SignRequestBuilder<String, Payload, DomainId> {
    pub fn build(self) -> SignRequestArgs {
        SignRequestArgs {
            path: self.path,
            payload: self.payload,
            domain_id: self.domain_id,
        }
    }
}

#[cfg(test)]
mod test {}
