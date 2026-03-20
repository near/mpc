use serde::{Deserialize, Serialize};

use near_mpc_contract_interface::types::Bls12381G1PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, derive_more::Constructor)]
pub struct CKDResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}
