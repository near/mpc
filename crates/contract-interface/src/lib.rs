#![doc = include_str!("../README.md")]
#![deny(clippy::mod_module_files)]
pub mod method_names;
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
    pub use participants::{ParticipantId, ParticipantInfo, Participants};

    pub use metrics::Metrics;
    pub use primitives::{
        AccountId, CkdAppId, DomainId, Ed25519Signature, K256AffinePoint, K256Scalar,
        K256Signature, SignatureResponse, Tweak,
    };
    pub use sign::*;
    pub use state::{
        AddDomainsVotes, AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId,
        DomainConfig, DomainPurpose, DomainRegistry, EpochId, InitializingContractState, KeyEvent,
        KeyEventId, KeyEventInstance, KeyForDomain, Keyset, ProtocolContractState,
        PublicKeyExtended, ResharingContractState, RunningContractState, SignatureScheme,
        Threshold, ThresholdParameters, ThresholdParametersVotes,
    };
    pub use updates::{ProposedUpdates, UpdateHash};

    mod attestation;
    mod config;
    mod crypto;
    mod foreign_chain;
    mod metrics;
    mod participants;
    mod primitives;
    mod sign;
    mod state;
    mod updates;
}
