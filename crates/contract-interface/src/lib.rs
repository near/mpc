#![doc = include_str!("../README.md")]
#![deny(clippy::mod_module_files)]
pub mod types {
    pub use attestation::{
        AppCompose, Attestation, Collateral, DstackAttestation, EventLog, MockAttestation, TcbInfo,
    };

    pub use crypto::{
        Bls12381G1PublicKey, Bls12381G2PublicKey, Ed25519PublicKey, PublicKey, Secp256k1PublicKey,
    };

    mod attestation;
    mod crypto;
}
