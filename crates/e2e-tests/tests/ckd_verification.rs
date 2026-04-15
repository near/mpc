use crate::common;

use blstrs::{G1Projective, G2Projective, Scalar};
use group::Group as _;
use group::ff::Field as _;
use mpc_contract::crypto_shared::kdf::derive_app_id;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, Bls12381G2PublicKey, CKDAppPublicKey, CKDAppPublicKeyPV, Curve,
    DomainPurpose,
};
use rand::SeedableRng;
use threshold_signatures::confidential_key_derivation::{
    CKDOutput, VerifyingKey, ciphersuite::verify_signature,
};

// derivation_path sent by send_ckd_request
const DERIVATION_PATH: &str = "test";

fn verify_ckd(
    account_id: &AccountId,
    path: &str,
    mpc_public_key: &Bls12381G2PublicKey,
    private_key: Scalar,
    big_y: &Bls12381G1PublicKey,
    big_c: &Bls12381G1PublicKey,
) -> bool {
    let big_y = G1Projective::try_from(big_y).expect("invalid big_y G1 point");
    let big_c = G1Projective::try_from(big_c).expect("invalid big_c G1 point");
    let mpc_pk = G2Projective::try_from(mpc_public_key).expect("invalid MPC G2 key");

    let mpc_vk = VerifyingKey::new(mpc_pk);
    let confidential_key = CKDOutput::new(big_y, big_c).unmask(private_key);
    let app_id = derive_app_id(account_id, path);

    verify_signature(&mpc_vk, app_id.as_ref(), &confidential_key).is_ok()
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
        .find(|d| d.curve == Curve::Bls12381 && matches!(d.purpose, DomainPurpose::CKD))
        .expect("no Bls12381 CKD domain found")
        .clone();

    let mpc_pk = common::bls_public_key(&running, bls_domain.id);

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

    assert!(
        verify_ckd(
            cluster.default_user_account(),
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
        .find(|d| d.curve == Curve::Bls12381 && matches!(d.purpose, DomainPurpose::CKD))
        .expect("no Bls12381 CKD domain found")
        .clone();

    let mpc_pk = common::bls_public_key(&running, bls_domain.id);

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
        .send_ckd_request(bls_domain.id, app_public_key)
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

    assert!(
        verify_ckd(
            cluster.default_user_account(),
            DERIVATION_PATH,
            &mpc_pk,
            private_key,
            &big_y,
            &big_c
        ),
        "CKD PV response failed cryptographic verification"
    );
}
