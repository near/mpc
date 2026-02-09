use contract_interface::types::{self as dtos, Bls12381G1PublicKey};
use k256::elliptic_curve::{sec1::ToEncodedPoint as _, Field as _, Group as _, PrimeField as _};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        signature::Tweak,
    },
};
use rand::rngs::OsRng;
use rand_core::CryptoRngCore;
use threshold_signatures::{
    blstrs,
    confidential_key_derivation::{self as ckd},
    ecdsa as ts_ecdsa, eddsa,
    frost_ed25519::{keys::SigningShare, Ed25519Group, Group as _, VerifyingKey},
    frost_secp256k1::{self, Secp256K1Group},
};

#[derive(Debug, Clone)]
pub struct DomainKey {
    pub domain_config: DomainConfig,
    pub domain_secret_key: SharedSecretKey,
    pub domain_public_key: PublicKeyExtended,
}

impl DomainKey {
    pub fn domain_id(&self) -> DomainId {
        self.domain_config.id
    }
}

#[derive(Debug, Clone)]
pub enum SharedSecretKey {
    Secp256k1(ts_ecdsa::KeygenOutput),
    Ed25519(eddsa::KeygenOutput),
    Bls12381(ckd::KeygenOutput),
}

pub fn new_secp256k1() -> (dtos::PublicKey, ts_ecdsa::KeygenOutput) {
    let scalar = k256::Scalar::random(&mut rand::thread_rng());
    let private_share = frost_secp256k1::keys::SigningShare::new(scalar);
    let public_key_element = Secp256K1Group::generator() * scalar;
    let public_key = frost_secp256k1::VerifyingKey::new(public_key_element);

    let keygen_output = ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_encoded_point(false);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&compressed_key.as_bytes()[1..]);
    let pk = dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey::from(bytes));

    (pk, keygen_output)
}

pub fn make_key_for_domain(domain_scheme: SignatureScheme) -> (dtos::PublicKey, SharedSecretKey) {
    match domain_scheme {
        SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
            let (pk, sk) = new_secp256k1();
            (pk, SharedSecretKey::Secp256k1(sk))
        }
        SignatureScheme::Ed25519 => {
            let (pk, sk) = new_ed25519();
            (pk, SharedSecretKey::Ed25519(sk))
        }
        SignatureScheme::Bls12381 => {
            let (pk, sk) = new_bls12381();
            (pk, SharedSecretKey::Bls12381(sk))
        }
    }
}

pub fn new_ed25519() -> (dtos::PublicKey, eddsa::KeygenOutput) {
    let scalar = curve25519_dalek::Scalar::random(&mut OsRng);
    let private_share = SigningShare::new(scalar);
    let public_key_element = Ed25519Group::generator() * scalar;
    let public_key = VerifyingKey::new(public_key_element);

    let keygen_output = eddsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().compress().as_bytes().to_vec();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&compressed_key);
    let pk = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey::from(bytes));

    (pk, keygen_output)
}

pub fn new_bls12381() -> (dtos::PublicKey, ckd::KeygenOutput) {
    let scalar = ckd::Scalar::random(&mut OsRng);
    let private_share = ckd::SigningShare::new(scalar);
    let public_key_element = ckd::ElementG2::generator() * scalar;
    let public_key = ckd::VerifyingKey::new(public_key_element);

    let keygen_output = ckd::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_compressed();
    let pk = dtos::PublicKey::from(dtos::Bls12381G2PublicKey::from(compressed_key));

    (pk, keygen_output)
}

pub fn derive_secret_key_secp256k1(
    secret_key: &ts_ecdsa::KeygenOutput,
    tweak: &Tweak,
) -> ts_ecdsa::KeygenOutput {
    let tweak = k256::Scalar::from_repr(tweak.as_bytes().into()).unwrap();
    let private_share =
        frost_secp256k1::keys::SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key = frost_secp256k1::VerifyingKey::new(
        secret_key.public_key.to_element() + Secp256K1Group::generator() * tweak,
    );
    ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    }
}

pub fn derive_secret_key_ed25519(
    secret_key: &eddsa::KeygenOutput,
    tweak: &Tweak,
) -> eddsa::KeygenOutput {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    let private_share = SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key =
        VerifyingKey::new(secret_key.public_key.to_element() + Ed25519Group::generator() * tweak);

    eddsa::KeygenOutput {
        private_share,
        public_key,
    }
}

pub fn generate_random_app_public_key(rng: &mut impl CryptoRngCore) -> Bls12381G1PublicKey {
    let x = blstrs::Scalar::random(rng);
    let big_x = blstrs::G1Projective::generator() * x;
    Bls12381G1PublicKey::from(big_x.to_compressed())
}
