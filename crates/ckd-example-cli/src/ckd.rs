use anyhow::{Context as _, Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use elliptic_curve::{Field as _, Group as _, group::prime::PrimeCurveAffine as _};
use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::io::{self, Write as _};

use near_mpc_contract_interface::types::{
    AccountId, Bls12381G1PublicKey, Bls12381G2PublicKey, CKDAppPublicKey, CKDAppPublicKeyPV,
    CKDRequestArgs, CkdAppId,
};

use crate::{cli::Args, types::CKDResponse};

const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
const OUTPUT_SECRET_SIZE: usize = 32;
const HKDF_SALT: &[u8] = b"near-mpc-ckd-hkdf-v1";
const HKDF_INFO_STRONG_KEY: &[u8] = b"near-mpc-ckd-strong-key-v1";

pub fn run(args: Args) -> Result<()> {
    let account_id: AccountId = args.signer_account_id.parse()?;
    let app_id = derive_app_id(&account_id, &args.derivation_path);

    let (ephemeral_private_key, app_public_key) = if args.publicly_verifiable {
        let (scalar, pk1, pk2) = generate_ephemeral_key_pv(&mut OsRng);
        (
            scalar,
            CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV { pk1, pk2 }),
        )
    } else {
        let (scalar, pk) = generate_ephemeral_key(&mut OsRng);
        (scalar, CKDAppPublicKey::AppPublicKey(pk))
    };
    let ckd_params = CKDRequestArgs {
        derivation_path: args.derivation_path,
        app_public_key,
        domain_id: args.domain_id,
    };
    let function_name = near_mpc_contract_interface::method_names::REQUEST_APP_PRIVATE_KEY;
    println!("Call the function {function_name} with parameters:");

    let ckd_params_json = serde_json::to_string(&serde_json::json!({"request": ckd_params}))?;
    println!("{ckd_params_json}");

    let example_ckd_response = "{\"big_c\": \"bls12381g1:...\",\"big_y\": \"bls12381g1:...\"}";
    println!("Please enter a the response in json format (for example {example_ckd_response}):");

    let ckd_response = read_response()?;

    let key = compute_app_key(
        &ckd_response,
        ephemeral_private_key,
        app_id,
        &args.mpc_ckd_public_key,
    )?;
    let key_hex = hex::encode(key);

    println!("The key is: {key_hex}");
    Ok(())
}

fn read_response() -> Result<CKDResponse> {
    print!("Your response: ");
    io::stdout().flush()?;
    let mut json_response = String::new();
    for _ in 0..5 {
        let mut current_line = String::new();
        io::stdin().read_line(&mut current_line)?;
        json_response += &current_line;
        if current_line.contains("}") {
            break;
        }
    }
    Ok(serde_json::from_str(&json_response)?)
}

fn generate_ephemeral_key(rng: &mut impl CryptoRngCore) -> (Scalar, Bls12381G1PublicKey) {
    let x = blstrs::Scalar::random(rng);
    let big_x = blstrs::G1Projective::generator() * x;
    (x, Bls12381G1PublicKey::from(&big_x))
}

fn generate_ephemeral_key_pv(
    rng: &mut impl CryptoRngCore,
) -> (Scalar, Bls12381G1PublicKey, Bls12381G2PublicKey) {
    let x = blstrs::Scalar::random(rng);
    let pk1 = blstrs::G1Projective::generator() * x;
    let pk2 = blstrs::G2Projective::generator() * x;
    (
        x,
        Bls12381G1PublicKey::from(&pk1),
        Bls12381G2PublicKey::from(&pk2),
    )
}

pub fn verify(public_key: &G2Projective, app_id: &[u8], signature: &G1Projective) -> bool {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return false;
    }
    let element2: G2Affine = public_key.into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return false;
    }

    let hash_input = [public_key.to_compressed().as_slice(), app_id].concat();
    let base1 = G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]).into();
    let base2 = G2Affine::generator();

    blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2))
}

fn compute_app_key(
    response: &CKDResponse,
    ephemeral_private_key: Scalar,
    app_id: CkdAppId,
    mpc_public_key: &Bls12381G2PublicKey,
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    let secret = decrypt_secret_and_verify(
        &response.big_y,
        &response.big_c,
        ephemeral_private_key,
        app_id,
        mpc_public_key,
    )?;
    derive_strong_key(secret, HKDF_INFO_STRONG_KEY)
}

fn decrypt_secret_and_verify(
    big_y: &Bls12381G1PublicKey,
    big_c: &Bls12381G1PublicKey,
    private_key: Scalar,
    app_id: CkdAppId,
    mpc_public_key: &Bls12381G2PublicKey,
) -> Result<[u8; BLS12381G1_PUBLIC_KEY_SIZE]> {
    let big_y: G1Projective = big_y.try_into().context("invalid G1 point")?;
    let big_c: G1Projective = big_c.try_into().context("invalid G1 point")?;
    let mpc_public_key: G2Projective = mpc_public_key.try_into().context("invalid G2 point")?;

    // decrypt the secret
    let secret = big_c - big_y * private_key;

    // verify the secret
    if !verify(&mpc_public_key, app_id.as_ref(), &secret) {
        anyhow::bail!("Verification failed!");
    }

    // return the secret as bytes
    Ok(secret.to_compressed())
}

/// The HKDF salt and `info` instantiation is chosen by the application and is not part of
/// the CKD protocol; the values here are this example's convention. Callers deriving
/// multiple keys from the same CKD output should use a distinct `info` per key purpose,
/// so that keys for different purposes are cryptographically unrelated.
fn derive_strong_key(
    ikm: [u8; BLS12381G1_PUBLIC_KEY_SIZE],
    info: &[u8],
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; OUTPUT_SECRET_SIZE];
    hk.expand(info, &mut okm).map_err(|err| anyhow!("{err}"))?;
    Ok(okm)
}

const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";

pub fn derive_app_id(account_id: &AccountId, path: &str) -> CkdAppId {
    let derivation_path = format!("{APP_ID_DERIVATION_PREFIX}{},{}", account_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    hash.into()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rand::{SeedableRng as _, rngs::StdRng};
    use rstest::rstest;

    /// Plays the MPC side of the CKD exchange: `sig = msk · H(pk, app_id)` encrypted
    /// as `(Y, C) = (y·G1, sig + y·a·G1)` against the app's ephemeral key `a`.
    fn simulate_ckd_response(
        msk: Scalar,
        ephemeral_private_key: Scalar,
        app_id: &CkdAppId,
        rng: &mut impl CryptoRngCore,
    ) -> (G2Projective, G1Projective, CKDResponse) {
        let mpc_public_key = G2Projective::generator() * msk;
        let hash_input = [mpc_public_key.to_compressed().as_slice(), app_id.as_ref()].concat();
        let sig = G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]) * msk;

        let y = Scalar::random(rng);
        let big_y = G1Projective::generator() * y;
        let big_c = sig + G1Projective::generator() * (ephemeral_private_key * y);
        let response = CKDResponse::new(
            Bls12381G1PublicKey::from(&big_y),
            Bls12381G1PublicKey::from(&big_c),
        );
        (mpc_public_key, sig, response)
    }

    #[test]
    fn compute_app_key__should_derive_strong_key_with_purpose_tagged_info() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let msk = Scalar::random(&mut rng);
        let ephemeral_private_key = Scalar::random(&mut rng);
        let app_id = CkdAppId::from([9u8; 32]);
        let (mpc_public_key, sig, response) =
            simulate_ckd_response(msk, ephemeral_private_key, &app_id, &mut rng);
        let mut expected = [0u8; OUTPUT_SECRET_SIZE];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), &sig.to_compressed())
            .expand(HKDF_INFO_STRONG_KEY, &mut expected)
            .unwrap();

        // When
        let key = compute_app_key(
            &response,
            ephemeral_private_key,
            app_id,
            &Bls12381G2PublicKey::from(&mpc_public_key),
        )
        .unwrap();

        // Then
        assert_eq!(key, expected);
    }

    #[test]
    fn derive_strong_key__should_use_nonempty_salt() {
        // Given
        let ikm = [7u8; BLS12381G1_PUBLIC_KEY_SIZE];
        let info = b"some-info";
        let mut unsalted = [0u8; OUTPUT_SECRET_SIZE];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(info, &mut unsalted)
            .unwrap();

        // When
        let key = derive_strong_key(ikm, info).unwrap();

        // Then
        assert_ne!(key, unsalted);
    }

    #[rstest]
    #[case(b"purpose-a", b"purpose-b")]
    #[case(b"", HKDF_INFO_STRONG_KEY)]
    fn derive_strong_key__should_produce_different_keys_for_different_info(
        #[case] info_a: &[u8],
        #[case] info_b: &[u8],
    ) {
        // Given
        let ikm = [3u8; BLS12381G1_PUBLIC_KEY_SIZE];

        // When
        let key_a = derive_strong_key(ikm, info_a).unwrap();
        let key_b = derive_strong_key(ikm, info_b).unwrap();

        // Then
        assert_ne!(key_a, key_b);
    }
}
