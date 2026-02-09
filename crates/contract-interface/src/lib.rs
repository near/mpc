#![doc = include_str!("../README.md")]
#![deny(clippy::mod_module_files)]
pub mod types {
    pub use attestation::{
        AppCompose, Attestation, Collateral, DstackAttestation, EventLog, MockAttestation, TcbInfo,
        VerifiedAttestation, VerifiedDstackAttestation,
    };
    pub use config::{Config, InitConfig};
    pub use crypto::{
        Bls12381G1PublicKey, Bls12381G2PublicKey, Ed25519PublicKey, PublicKey, Secp256k1PublicKey,
    };
    pub use foreign_chain::*;

    pub use primitives::{
        AccountId, CkdAppId, K256AffinePoint, K256Scalar, K256Signature, SignatureResponse, Tweak,
    };
    pub use updates::{ProposedUpdates, UpdateHash};

    mod attestation;
    mod config;
    mod crypto;
    mod foreign_chain;
    mod primitives;
    mod updates;
}
