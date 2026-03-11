#![doc = include_str!("../README.md")]
#![deny(clippy::mod_module_files)]
pub mod method_names;
pub mod types {
    pub use attestation::{
        AppCompose, Attestation, Collateral, DstackAttestation, EventLog, MockAttestation, TcbInfo,
        VerifiedAttestation, VerifiedDstackAttestation,
    };
    pub use config::{Config, InitConfig};
    pub use foreign_chain::*;
    pub use participants::{ParticipantId, ParticipantInfo, Participants};

    pub use metrics::Metrics;
    pub use primitives::{AccountId, CkdAppId, DomainId, Tweak};
    pub use sign::*;
    pub use state::{
        AddDomainsVotes, AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId,
        DomainConfig, DomainPurpose, DomainRegistry, EpochId, InitializingContractState, KeyEvent,
        KeyEventId, KeyEventInstance, KeyForDomain, Keyset, ProtocolContractState,
        ResharingContractState, RunningContractState, SignatureScheme, Threshold,
        ThresholdParameters, ThresholdParametersVotes,
    };
    pub use updates::{ProposedUpdates, UpdateHash};

    // Re-export crypto types from mpc-crypto-types
    pub use mpc_crypto_types::{
        Bls12381G1PublicKey, Bls12381G2PublicKey, CryptoConversionError, Ed25519PublicKey,
        Ed25519Signature, K256AffinePoint, K256Scalar, K256Signature, ParsePublicKeyError,
        PublicKey, PublicKeyExtended, Secp256k1PublicKey, SignatureResponse,
    };

    mod attestation;
    mod config;
    mod foreign_chain;
    mod metrics;
    mod participants;
    mod primitives;
    mod sign;
    mod state;
    mod updates;
}

#[cfg(feature = "blstrs")]
pub use mpc_crypto_types::blstrs;

#[cfg(feature = "near")]
pub use mpc_crypto_types::near_sdk;

#[cfg(feature = "k256")]
pub use mpc_crypto_types::k256;

#[cfg(feature = "ed25519-dalek")]
pub use mpc_crypto_types::curve25519_dalek;
#[cfg(feature = "ed25519-dalek")]
pub use mpc_crypto_types::ed25519_dalek;
