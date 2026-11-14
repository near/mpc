#![expect(non_snake_case)]

use crate::common::{
    CKD_PV_VERIFICATION_PORT_SEED, CKD_VERIFICATION_PORT_SEED, must_get_bls_public_key,
    must_get_domain, must_setup_cluster,
};

use anyhow::Context;
use blstrs::{G1Projective, G2Projective, Scalar};
use group::Group as _;
use group::ff::Field as _;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::kdf::derive_app_id;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, Bls12381G2PublicKey, CKDAppPublicKey, CKDAppPublicKeyPV, Protocol,
};
use rand::SeedableRng;
use rstest::rstest;
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
) -> anyhow::Result<bool> {
    let big_y = G1Projective::try_from(big_y).context("invalid big_y G1 point")?;
    let big_c = G1Projective::try_from(big_c).context("invalid big_c G1 point")?;
    let mpc_pk = G2Projective::try_from(mpc_public_key).context("invalid MPC G2 key")?;

    let mpc_vk = VerifyingKey::new(mpc_pk);
    let confidential_key = CKDOutput::new(big_y, big_c).unmask(private_key);
    let app_id = derive_app_id(account_id, path);

    Ok(verify_signature(&mpc_vk, app_id.as_ref(), &confidential_key).is_ok())
}

fn app_public_key(private_key: Scalar) -> CKDAppPublicKey {
    CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(
        &(G1Projective::generator() * private_key),
    ))
}

fn app_public_key_pv(private_key: Scalar) -> CKDAppPublicKey {
    CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
        pk1: Bls12381G1PublicKey::from(&(G1Projective::generator() * private_key)),
        pk2: Bls12381G2PublicKey::from(&(G2Projective::generator() * private_key)),
    })
}

#[rstest]
#[case::app_public_key(CKD_VERIFICATION_PORT_SEED, 1, app_public_key)]
#[case::publicly_verifiable_app_public_key(CKD_PV_VERIFICATION_PORT_SEED, 2, app_public_key_pv)]
#[tokio::test]
async fn ckd_response__passes_cryptographic_verification(
    #[case] port_seed: u16,
    #[case] rng_seed: u64,
    #[case] to_app_public_key: fn(Scalar) -> CKDAppPublicKey,
) {
    // given
    let (cluster, running) = must_setup_cluster(port_seed, |_| {}).await;

    let bls_domain = must_get_domain(&running, Protocol::ConfidentialKeyDerivation);

    let mpc_pk = must_get_bls_public_key(&running, bls_domain.id);
    let user = cluster.default_user_account().clone();

    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let private_key = Scalar::random(&mut rng);
    let app_public_key = to_app_public_key(private_key);

    // when
    let outcome = cluster
        .send_ckd_request(bls_domain.id, app_public_key, &user)
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
        verify_ckd(&user, DERIVATION_PATH, &mpc_pk, private_key, &big_y, &big_c)
            .expect("verify_ckd failed"),
        "CKD response failed cryptographic verification"
    );
}
