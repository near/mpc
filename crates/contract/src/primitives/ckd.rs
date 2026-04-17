use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective};
use elliptic_curve::Group as _;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::kdf::derive_app_id;
use near_mpc_contract_interface::types::{CKDResponse, DomainId};
use near_sdk::{env, near};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct CKDRequest {
    /// The app ephemeral public key
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
    pub domain_id: DomainId,
}

impl CKDRequest {
    pub fn new(
        app_public_key: dtos::CKDAppPublicKey,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        derivation_path: &str,
    ) -> Self {
        let app_id = derive_app_id(predecessor_id, derivation_path);
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}

/// Check that `e(app_pk1, g2) = e(g1, app_pk2)`
pub(crate) fn app_public_key_check(app_public_key: &dtos::CKDAppPublicKeyPV) -> bool {
    let Some(pk1) = G1Affine::from_compressed(&app_public_key.pk1).into_option() else {
        return false;
    };
    let Some(pk2) = G2Affine::from_compressed(&app_public_key.pk2).into_option() else {
        return false;
    };
    if !check_valid_point_g1(&pk1) || !check_valid_point_g2(&pk2) {
        return false;
    }

    let g1 = G1Projective::generator().to_uncompressed().to_vec();
    let minus_g2 = (-G2Projective::generator()).to_uncompressed().to_vec();

    let pk1 = env::bls12381_p1_decompress(&app_public_key.pk1);
    let pk2 = env::bls12381_p2_decompress(&app_public_key.pk2);

    let pairing_input = [pk1, minus_g2, g1, pk2].concat();
    env::bls12381_pairing_check(&pairing_input)
}

/// Check that `e(big_c, g2) = e(big_y, app_pk2) . e(hash_point, public_key)`
pub(crate) fn ckd_output_check(
    app_id: &dtos::CkdAppId,
    output: &CKDResponse,
    app_public_key: &dtos::CKDAppPublicKeyPV,
    public_key: &dtos::Bls12381G2PublicKey,
) -> bool {
    let Some(big_c) = G1Affine::from_compressed(&output.big_c).into_option() else {
        return false;
    };
    let Some(big_y) = G1Affine::from_compressed(&output.big_y).into_option() else {
        return false;
    };
    if !check_valid_point_g1(&big_c) || !check_valid_point_g1(&big_y) {
        return false;
    }

    let minus_g2 = (-G2Projective::generator()).to_uncompressed().to_vec();
    let big_c = env::bls12381_p1_decompress(&output.big_c);
    let big_y = env::bls12381_p1_decompress(&output.big_y);
    let pk2 = env::bls12381_p2_decompress(&app_public_key.pk2);
    let pk = env::bls12381_p2_decompress(public_key);
    let hash_point = hash_app_id_with_pk(public_key.as_slice(), app_id.as_ref())
        .to_uncompressed()
        .to_vec();
    let pairing_input = [big_c, minus_g2, big_y, pk2, hash_point, pk].concat();
    env::bls12381_pairing_check(&pairing_input)
}

/// Hashes the app id and the public key as of
/// H(pk || `app_id`) where H is a random oracle
fn hash_app_id_with_pk(pk: &[u8], app_id: &[u8]) -> G1Projective {
    let input = [pk, app_id].concat();
    hash_to_curve(&input)
}

fn check_valid_point_g1(p: &G1Affine) -> bool {
    (p.is_on_curve() & p.is_torsion_free()).into()
}

fn check_valid_point_g2(p: &G2Affine) -> bool {
    (p.is_on_curve() & p.is_torsion_free()).into()
}

/// Confidential key derivation domain separator.
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn hash_to_curve(bytes: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(bytes, NEAR_CKD_DOMAIN, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::Scalar;
    use elliptic_curve::group::Curve as _;
    use elliptic_curve::Field as _;
    use threshold_signatures::confidential_key_derivation::{self as ckd, ElementG2, VerifyingKey};

    #[test]
    fn check_valid_point_g1_accepts_generator() {
        let g = G1Projective::generator().to_affine();
        assert!(check_valid_point_g1(&g));
    }

    #[test]
    fn check_valid_point_g1_accepts_identity() {
        // The identity point is on-curve and torsion-free in blstrs.
        // Rejecting identity is the caller's responsibility if needed.
        let identity = G1Projective::identity().to_affine();
        assert!(check_valid_point_g1(&identity));
    }

    #[test]
    fn check_valid_point_g1_accepts_random_point() {
        let p = (G1Projective::generator() * Scalar::random(rand::rngs::OsRng)).to_affine();
        assert!(check_valid_point_g1(&p));
    }

    #[test]
    fn check_valid_point_g2_accepts_generator() {
        let g = G2Projective::generator().to_affine();
        assert!(check_valid_point_g2(&g));
    }

    #[test]
    fn check_valid_point_g2_accepts_identity() {
        let identity = G2Projective::identity().to_affine();
        assert!(check_valid_point_g2(&identity));
    }

    #[test]
    fn hash_to_curve_is_deterministic() {
        let input = b"test input";
        let p1 = hash_to_curve(input);
        let p2 = hash_to_curve(input);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_to_curve_produces_valid_point() {
        let p = hash_to_curve(b"some data").to_affine();
        assert!(check_valid_point_g1(&p));
    }

    #[test]
    fn hash_to_curve_different_inputs_produce_different_points() {
        let p1 = hash_to_curve(b"input a");
        let p2 = hash_to_curve(b"input b");
        assert_ne!(p1, p2);
    }

    #[test]
    fn hash_app_id_with_pk_is_deterministic() {
        let pk = G2Projective::generator().to_compressed();
        let app_id = [42u8; 32];
        let p1 = hash_app_id_with_pk(&pk, &app_id);
        let p2 = hash_app_id_with_pk(&pk, &app_id);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_app_id_with_pk_produces_valid_point() {
        let pk = G2Projective::generator().to_compressed();
        let app_id = [1u8; 32];
        let p = hash_app_id_with_pk(&pk, &app_id).to_affine();
        assert!(check_valid_point_g1(&p));
    }

    /// The contract's `hash_app_id_with_pk` must produce the same output as
    /// `threshold_signatures::confidential_key_derivation::hash_app_id_with_pk`
    /// for the same inputs, since nodes and the contract must agree on the hash point.
    #[test]
    fn hash_app_id_with_pk_matches_threshold_signatures_crate() {
        let scalar = Scalar::random(rand::rngs::OsRng);
        let pk_element = ElementG2::generator() * scalar;
        let vk = VerifyingKey::new(pk_element);
        let app_id = [7u8; 32];

        // threshold-signatures crate version
        let ts_result = ckd::hash_app_id_with_pk(&vk, &app_id);

        // contract version: takes raw compressed pk bytes
        let compressed_pk = pk_element.to_compressed();
        let contract_result = hash_app_id_with_pk(compressed_pk.as_slice(), &app_id);

        assert_eq!(
            ts_result, contract_result,
            "contract and threshold-signatures hash_app_id_with_pk must agree"
        );
    }

    #[test]
    fn hash_app_id_with_pk_snapshot() {
        let pk = G2Projective::generator().to_compressed();
        let app_id = [0u8; 32];
        let result = hash_app_id_with_pk(&pk, &app_id);
        let compressed = hex::encode(result.to_compressed());
        insta::assert_snapshot!(compressed);
    }

    #[test]
    fn ckd_request_new_derives_app_id_deterministically() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let pk = dtos::CKDAppPublicKey::AppPublicKey(dtos::Bls12381G1PublicKey([1u8; 48]));
        let domain_id = DomainId(0);

        let r1 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        let r2 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        assert_eq!(r1.app_id, r2.app_id);

        let r3 = CKDRequest::new(pk, domain_id, &account_id, "path/b");
        assert_ne!(r1.app_id, r3.app_id);
    }
}
