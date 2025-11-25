use serde::{Deserialize, Serialize};

use contract_interface::types::Bls12381G1PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, derive_more::Constructor)]
pub struct CKDResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, derive_more::Constructor)]
pub struct CKDArgs {
    pub app_public_key: Bls12381G1PublicKey,
    pub domain_id: DomainId,
}

#[derive(Clone, Debug, Serialize, Deserialize, derive_more::Constructor)]
pub struct CKDRequestArgs {
    pub request: CKDArgs,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    derive_more::Constructor,
    derive_more::FromStr,
)]
pub struct DomainId(pub u64);
