use blstrs::Scalar;
use elliptic_curve::{Field as _, Group as _};
use rand::RngCore;

use crate::confidential_key_derivation::{AppId, ElementG1, ElementG2, PublicVerificationKey};

pub fn generate_ckd_app_package(rng: &mut impl RngCore) -> (AppId, Scalar, PublicVerificationKey) {
    let app_id = AppId::try_from(b"Near App").unwrap();
    let app_sk = Scalar::random(rng);
    let app_pk = PublicVerificationKey::new(
        ElementG1::generator() * app_sk,
        ElementG2::generator() * app_sk,
    );
    (app_id, app_sk, app_pk)
}
