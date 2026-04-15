use crate::common;

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use e2e_tests::CKD_PV_GAS;
use group::Group as _;
use group::ff::Field as _;
use group::prime::PrimeCurveAffine as _;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, Bls12381G2PublicKey, CKDAppPublicKey, CKDAppPublicKeyPV, Curve, DomainId,
    DomainPurpose, PublicKey, PublicKeyExtended, RunningContractState,
};
use rand::SeedableRng;
use sha3::{Digest, Sha3_256};

const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";
// derivation_path sent by send_ckd_request
const DERIVATION_PATH: &str = "test";

fn derive_app_id(account_id: &str, path: &str) -> [u8; 32] {
    let input = format!("{APP_ID_DERIVATION_PREFIX}{account_id},{path}");
    let mut h = Sha3_256::new();
    h.update(input.as_bytes());
    h.finalize().into()
}

/// Verify the CKD response: decrypt via ElGamal, then check the BLS pairing.
fn verify_ckd(
    account_id: &str,
    path: &str,
    mpc_public_key: &Bls12381G2PublicKey,
    private_key: Scalar,
    big_y: &Bls12381G1PublicKey,
    big_c: &Bls12381G1PublicKey,
) -> bool {
    let big_y = G1Projective::try_from(big_y).expect("invalid big_y G1 point");
    let big_c = G1Projective::try_from(big_c).expect("invalid big_c G1 point");
    let mpc_pk = G2Projective::try_from(mpc_public_key).expect("invalid MPC G2 key");

    let secret: G1Affine = (big_c - big_y * private_key).into();
    let mpc_pk_affine: G2Affine = mpc_pk.into();

    let app_id = derive_app_id(account_id, path);
    let hash_input = [mpc_public_key.as_slice(), &app_id].concat();
    let hash_point: G1Affine =
        G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]).into();

    blstrs::pairing(&hash_point, &mpc_pk_affine) == blstrs::pairing(&secret, &G2Affine::generator())
}

fn bls_public_key(running: &RunningContractState, domain_id: DomainId) -> Bls12381G2PublicKey {
    let key_for_domain = running
        .keyset
        .domains
        .iter()
        .find(|k| k.domain_id == domain_id)
        .expect("no key found for BLS12381 domain");
    match &key_for_domain.key {
        PublicKeyExtended::Bls12381 {
            public_key: PublicKey::Bls12381(g2),
        } => g2.clone(),
        other => panic!("expected Bls12381 key, got {other:?}"),
    }
}

/// Verify that a CKD response (AppPublicKey variant) is mathematically correct.
#[tokio::test]
#[expect(non_snake_case)]
async fn ckd_response__passes_cryptographic_verification() {
    // given
    let (cluster, running) =
        common::setup_cluster(common::CKD_VERIFICATION_PORT_SEED, |_| {}).await;

    let bls_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Bls12381 && matches!(d.purpose, Some(DomainPurpose::CKD)))
        .expect("no Bls12381 CKD domain found")
        .clone();

    let mpc_pk = bls_public_key(&running, bls_domain.id);

    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let private_key = Scalar::random(&mut rng);
    let app_public_key = CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(
        &(G1Projective::generator() * private_key),
    ));

    // when
    let outcome = cluster
        .send_ckd_request(bls_domain.id, app_public_key)
        .await
        .expect("CKD request transaction failed");

    // then
    assert!(
        outcome.is_success(),
        "CKD request failed: {:?}",
        outcome.failure_message()
    );

    let response: serde_json::Value = outcome.json().expect("failed to deserialize CKD response");
    let big_y: Bls12381G1PublicKey =
        serde_json::from_value(response["big_y"].clone()).expect("failed to parse big_y");
    let big_c: Bls12381G1PublicKey =
        serde_json::from_value(response["big_c"].clone()).expect("failed to parse big_c");

    let account_id = cluster.default_user_account().as_str();
    assert!(
        verify_ckd(
            account_id,
            DERIVATION_PATH,
            &mpc_pk,
            private_key,
            &big_y,
            &big_c
        ),
        "CKD response failed cryptographic verification"
    );
}

/// Verify that a CKD response (publicly verifiable AppPublicKeyPV variant) is mathematically correct.
#[tokio::test]
#[expect(non_snake_case)]
async fn ckd_pv_response__passes_cryptographic_verification() {
    // given
    let (cluster, running) =
        common::setup_cluster(common::CKD_PV_VERIFICATION_PORT_SEED, |_| {}).await;

    let bls_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Bls12381 && matches!(d.purpose, Some(DomainPurpose::CKD)))
        .expect("no Bls12381 CKD domain found")
        .clone();

    let mpc_pk = bls_public_key(&running, bls_domain.id);

    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let private_key = Scalar::random(&mut rng);
    let pk1 = G1Projective::generator() * private_key;
    let pk2 = G2Projective::generator() * private_key;
    let app_public_key = CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
        pk1: Bls12381G1PublicKey::from(&pk1),
        pk2: Bls12381G2PublicKey::from(&pk2),
    });

    // when
    let outcome = cluster
        .send_ckd_request_with_gas(bls_domain.id, app_public_key, CKD_PV_GAS)
        .await
        .expect("CKD PV request transaction failed");

    // then
    assert!(
        outcome.is_success(),
        "CKD PV request failed: {:?}",
        outcome.failure_message()
    );

    let response: serde_json::Value = outcome.json().expect("failed to deserialize CKD response");
    let big_y: Bls12381G1PublicKey =
        serde_json::from_value(response["big_y"].clone()).expect("failed to parse big_y");
    let big_c: Bls12381G1PublicKey =
        serde_json::from_value(response["big_c"].clone()).expect("failed to parse big_c");

    let account_id = cluster.default_user_account().as_str();
    assert!(
        verify_ckd(
            account_id,
            DERIVATION_PATH,
            &mpc_pk,
            private_key,
            &big_y,
            &big_c
        ),
        "CKD PV response failed cryptographic verification"
    );
}
