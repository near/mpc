use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use elliptic_curve::{Field as _, Group as _, group::prime::PrimeCurveAffine as _};
use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::io::{self, Write as _};

use contract_interface::types::{AccountId, Bls12381G1PublicKey, Bls12381G2PublicKey, CkdAppId};

use crate::{
    cli::Args,
    types::{CKDArgs, CKDRequestArgs, CKDResponse},
};

const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
const OUTPUT_SECRET_SIZE: usize = 32;

pub fn run(args: Args) -> Result<()> {
    let account_id = AccountId(args.signer_account_id);
    let app_id = derive_app_id(&account_id, &args.derivation_path);

    let (ephemeral_private_key, ephemeral_public_key) = generate_ephemeral_key(&mut OsRng);

    let ckd_params = CKDRequestArgs::new(CKDArgs::new(
        args.derivation_path,
        ephemeral_public_key,
        args.domain_id,
    ));
    let function_name = "request_app_private_key";
    println!("Call the function {function_name} with parameters:");

    let ckd_params_json = serde_json::to_string(&ckd_params)?;
    println!("{ckd_params_json}");

    let example_ckd_response = "{\"big_c\": \"bls12381g1:...\",\"big_y\": \"bls12381g1:...\"}";
    println!("Please enter a the response in json format (for example {example_ckd_response}):");

    let ckd_response = read_response()?;

    let secret = decrypt_secret_and_verify(
        ckd_response.big_y,
        ckd_response.big_c,
        ephemeral_private_key,
        app_id,
        args.mpc_ckd_public_key,
    )?;

    let key = derive_strong_key(secret, b"")?;
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
    (x, Bls12381G1PublicKey::from(big_x.to_compressed()))
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

fn decrypt_secret_and_verify(
    big_y: Bls12381G1PublicKey,
    big_c: Bls12381G1PublicKey,
    private_key: Scalar,
    app_id: CkdAppId,
    mpc_public_key: Bls12381G2PublicKey,
) -> Result<[u8; BLS12381G1_PUBLIC_KEY_SIZE]> {
    let big_y = convert_to_blstrs_type_g1(big_y)?;
    let big_c = convert_to_blstrs_type_g1(big_c)?;
    let mpc_public_key = convert_to_blstrs_type_g2(mpc_public_key)?;

    // decrypt the secret
    let secret = big_c - big_y * private_key;

    // verify the secret
    if !verify(&mpc_public_key, app_id.0.as_ref(), &secret) {
        anyhow::bail!("Verification failed!");
    }

    // return the secret as bytes
    Ok(secret.to_compressed())
}

fn convert_to_blstrs_type_g1(a: Bls12381G1PublicKey) -> Result<G1Projective> {
    G1Projective::from_compressed(a.as_bytes())
        .into_option()
        .ok_or(anyhow!("failed to convert"))
}

fn convert_to_blstrs_type_g2(a: Bls12381G2PublicKey) -> Result<G2Projective> {
    G2Projective::from_compressed(a.as_bytes())
        .into_option()
        .ok_or(anyhow!("failed to convert"))
}

fn derive_strong_key(
    ikm: [u8; BLS12381G1_PUBLIC_KEY_SIZE],
    info: &[u8],
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; OUTPUT_SECRET_SIZE];
    hk.expand(info, &mut okm).map_err(|err| anyhow!("{err}"))?;
    Ok(okm)
}

const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";

pub fn derive_app_id(account_id: &AccountId, path: &str) -> CkdAppId {
    let derivation_path = format!("{APP_ID_DERIVATION_PREFIX}{},{}", account_id.0, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    hash.into()
}
