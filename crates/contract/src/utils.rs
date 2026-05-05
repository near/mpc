use rand::rngs::OsRng;

use k256::elliptic_curve::{Field, Group};
use threshold_signatures::confidential_key_derivation as ckd;

use near_mpc_contract_interface::types as dtos;

pub fn random_app_public_key() -> dtos::Bls12381G1PublicKey {
    let x = ckd::Scalar::random(OsRng);
    let big_x = ckd::ElementG1::generator() * x;
    (&big_x).into()
}
