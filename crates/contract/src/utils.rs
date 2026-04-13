use rand::rngs::OsRng;

use k256::elliptic_curve::{Field, Group};
use threshold_signatures::confidential_key_derivation as ckd;

use near_mpc_contract_interface::types as dtos;

use crate::{dto_mapping::IntoInterfaceType, state::ProtocolContractState};

pub fn protocol_state_to_string(contract_state: &ProtocolContractState) -> String {
    let dto: dtos::ProtocolContractState = contract_state.into_dto_type();
    dto.to_string()
}

pub fn random_app_public_key() -> dtos::Bls12381G1PublicKey {
    let x = ckd::Scalar::random(OsRng);
    let big_x = ckd::ElementG1::generator() * x;
    (&big_x).into()
}
