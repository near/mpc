use contract_interface::types::{self as dtos, Bls12381G1PublicKey};
use k256::elliptic_curve::{Field as _, Group as _, PrimeField as _};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{Curve, DomainConfig, DomainId},
        signature::Tweak,
    },
};
use rand::rngs::OsRng;
use rand_core::CryptoRngCore;
use threshold_signatures::{
    blstrs,
    confidential_key_derivation::{self as ckd},
    ecdsa as ts_ecdsa,
    frost::eddsa,
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

    let pk = dtos::PublicKey::Secp256k1(
        dtos::Secp256k1PublicKey::try_from(public_key.to_element().to_affine())
            .expect("non-identity verifying key is a valid public key"),
    );

    (pk, keygen_output)
}

pub fn make_key_for_domain(domain_curve: Curve) -> (dtos::PublicKey, SharedSecretKey) {
    match domain_curve {
        Curve::Secp256k1 => {
            let (pk, sk) = new_secp256k1();
            (pk, SharedSecretKey::Secp256k1(sk))
        }
        Curve::Edwards25519 => {
            let (pk, sk) = new_ed25519();
            (pk, SharedSecretKey::Ed25519(sk))
        }
        Curve::Bls12381 => {
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

    let pk = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey::from(
        public_key.to_element().compress(),
    ));

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

    let pk = dtos::PublicKey::from(dtos::Bls12381G2PublicKey::from(&public_key.to_element()));

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
    Bls12381G1PublicKey::from(&big_x)
}
