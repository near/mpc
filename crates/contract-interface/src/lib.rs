#![doc = include_str!("../README.md")]
#![deny(clippy::mod_module_files)]
pub mod types {
    pub use attestation::{
        AppCompose, Attestation, Collateral, DstackAttestation, EventLog, MockAttestation, TcbInfo,
    };
    pub use config::{Config, InitConfig};
    pub use crypto::{
        Bls12381G1PublicKey, Bls12381G2PublicKey, Ed25519PublicKey, PublicKey, Secp256k1PublicKey,
    };
    pub use primitives::{AccountId, AppId};
    pub use updates::{ProposedUpdates, Update, UpdateHash};

    mod attestation;
    mod config;
    mod crypto;
    mod primitives;
    mod updates;
}
