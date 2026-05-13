use crate::crypto_shared::kdf::TweakNotOnCurve;
use crate::primitives::domain::MIN_RECONSTRUCTION_THRESHOLD;
use crate::primitives::key_state::{EpochId, Keyset};
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{Curve, DomainId, DomainPurpose, ForeignChain, Protocol};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeMigrationError {
    #[error("Node does not have an ongoing recovery")]
    MigrationNotFound,
    #[error("The transaction was submitted by a different public key than expected. Found: {found:?}, expected: {expected:?}")]
    AccountPublicKeyMismatch {
        found: near_sdk::PublicKey,
        expected: near_sdk::PublicKey,
    },
    #[error("The submitted keyset differs from the expected keyset. Found: {found:?}, expected: {expected:?}")]
    KeysetMismatch { found: Keyset, expected: Keyset },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TeeError {
    #[error("Due to previously failed TEE validation, the network is not accepting new requests at this point in time. Try again later.")]
    TeeValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("Request has timed out.")]
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespondError {
    #[error("The provided signature is invalid.")]
    InvalidSignature,
    #[error("The provided signature scheme does not match. MPC response: {mpc_scheme:?}, user request: {user_scheme:?}")]
    SignatureSchemeMismatch {
        mpc_scheme: Box<dtos::SignatureResponse>,
        user_scheme: Box<crate::crypto_shared::types::PublicKeyExtended>,
    },
    #[error("The provided domain was not found.")]
    DomainNotFound,
    #[error("The provided tweak is not on the curve of the public key.")]
    TweakNotOnCurve,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum PublicKeyError {
    #[error("The provided domain was not found.")]
    DomainNotFound,
    #[error("The provided tweak is not on the curve of the public key.")]
    TweakNotOnCurve,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum KeyEventError {
    #[error("Key event Id mismatch")]
    KeyEventIdMismatch,
    #[error("Can not start a new reshare or keygen instance while the current instance is still active.")]
    ActiveKeyEvent,
    #[error("Expected ongoing reshare")]
    NoActiveKeyEvent,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not the leader of the current reshare or keygen instance.")]
    VoterNotLeader,
    #[error("Vote already casted.")]
    VoteAlreadySubmitted,
    #[error(
        "Candidates can only cast a vote after `threshold` participants casted one to admit them"
    )]
    VoterPending,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidParameters {
    #[error("Malformed payload: {reason}")]
    MalformedPayload { reason: String },
    #[error("Attached deposit is lower than required. Attached: {attached}, required: {required}")]
    InsufficientDeposit { attached: u128, required: u128 },
    #[error("Provided gas is lower than required. Provided: {provided}, required: {required}")]
    InsufficientGas { provided: u64, required: u64 },
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
    #[error("Update not found.")]
    UpdateNotFound,
    #[error("Participant already in set.")]
    ParticipantAlreadyInSet,
    #[error("Participant id already used.")]
    ParticipantAlreadyUsed,
    #[error("The provided domain ID, {provided}, was not found.")]
    DomainNotFound { provided: DomainId },
    #[error("Provided Epoch Id, {provided}, does not match expected, {expected}.")]
    EpochMismatch {
        provided: EpochId,
        expected: EpochId,
    },
    #[error("Next domain ID mismatch")]
    NextDomainIdMismatch,
    #[error("Invalid domain ID.")]
    InvalidDomainId,
    #[error("Domain {domain_id} has purpose {actual:?}, but this method requires {expected:?}.")]
    WrongDomainPurpose {
        domain_id: DomainId,
        expected: DomainPurpose,
        actual: DomainPurpose,
    },
    #[error("Invalid TEE Remote Attestation: {reason}")]
    InvalidTeeRemoteAttestation { reason: String },
    #[error("Caller is not the signer account.")]
    CallerNotSigner,
    #[error("Requested foreign chain, {requested:?}, is not supported.")]
    ForeignChainNotSupported { requested: ForeignChain },
    #[error("The request_id supplied to respond is registered under a different request key.")]
    RequestMismatch,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidState {
    #[error("The protocol is not Running.")]
    ProtocolStateNotRunning,
    #[error("Protocol state is not resharing.")]
    ProtocolStateNotResharing,
    #[error("Protocol state is not initializing.")]
    ProtocolStateNotInitializing,
    #[error("Protocol state is not running, nor resharing.")]
    ProtocolStateNotRunningNorResharing,
    #[error("Unexpected protocol state: {state_name}")]
    UnexpectedProtocolState { state_name: &'static str },
    #[error("Cannot load in contract due to missing state")]
    ContractStateIsMissing,
    #[error("Participant index out of range")]
    ParticipantIndexOutOfRange,
    #[error("Not a participant: {account_id}")]
    NotParticipant { account_id: AccountId },
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidThreshold {
    #[error("Threshold does not meet the minimum absolute requirement")]
    MinAbsRequirementFailed,
    #[error("Threshold does not meet the minimum relative requirement: require at least {required}, found {found}")]
    MinRelRequirementFailed { required: u64, found: u64 },
    #[error("Threshold must not exceed number of participants: max {max}, found {found}")]
    MaxRequirementFailed { max: u64, found: u64 },
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidCandidateSet {
    #[error("Set of proposed participants must contain at least `threshold` old participants.")]
    InsufficientOldParticipants,
    #[error("Existing participant {account_id} changed ID from {old_id} to {new_id}.")]
    ParticipantIdChanged {
        account_id: AccountId,
        old_id: u32,
        new_id: u32,
    },
    #[error("Existing participant {account_id} changed info (url or tls_public_key).")]
    ParticipantInfoChanged { account_id: AccountId },
    #[error("New participant {account_id} reuses ID {new_id} already assigned to existing participant {existing_account_id}.")]
    NewParticipantReusesOldId {
        account_id: AccountId,
        new_id: u32,
        existing_account_id: AccountId,
    },
    #[error("Participant ID {id} is not less than next_id {next_id}.")]
    ParticipantIdNotLessThanNextId { id: u32, next_id: u32 },
    #[error("Duplicate participant IDs found.")]
    DuplicateParticipantIds,
    #[error("Duplicate account IDs found.")]
    DuplicateAccountIds,
    #[error("New Participant ids need to be unique and contiguous.")]
    NewParticipantIdsNotContiguous,
    #[error("New Participant ids need to not skip any unused participant ids.")]
    NewParticipantIdsTooHigh,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ConversionError {
    #[error("Data conversion error: {reason}")]
    DataConversion { reason: String },
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum DomainError {
    #[error("No such domain.")]
    NoSuchDomain,
    #[error("Newly proposed domain IDs are not contiguous. Expected id: {expected_id}")]
    NewDomainIdsNotContiguous { expected_id: DomainId },
    #[error("vote_add_domains must add at least one domain")]
    AddDomainsMustAddAtLeastOneDomain,
    #[error("Invalid list of domains provided")]
    InvalidDomains,
    #[error("Domains from keyset do not match the provided domains")]
    DomainsMismatch,
    #[error("Inconsistent curve/protocol pair: curve {curve:?} does not match protocol {protocol:?} (expected {expected:?})")]
    InconsistentCurveProtocol {
        curve: Curve,
        protocol: Protocol,
        expected: Curve,
    },
    #[error("Invalid protocol-purpose combination: protocol {protocol:?} is not compatible with purpose {purpose:?}")]
    InvalidProtocolPurposeCombination {
        protocol: Protocol,
        purpose: DomainPurpose,
    },
    #[error(
        "Reconstruction threshold must be at least {}.",
        MIN_RECONSTRUCTION_THRESHOLD
    )]
    ReconstructionThresholdTooLow,
    #[error("Reconstruction threshold {threshold} exceeds participant count {participants}.")]
    ReconstructionThresholdExceedsParticipants { threshold: u64, participants: u64 },
    #[error(
        "Protocol {protocol:?} requires at least {required} participants, found {participants}."
    )]
    InsufficientParticipantsForProtocol {
        protocol: Protocol,
        required: u64,
        participants: u64,
    },
    #[error(
        "Reconstruction threshold {threshold} overflowed when computing the DamgardEtAl bound."
    )]
    ReconstructionThresholdOverflow { threshold: u64 },
}

/// A list specifying general categories of MPC Contract errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An error occurred while node is performing respond call.
    #[error(transparent)]
    Respond(#[from] RespondError),
    /// An error occurred while user is performing public_key_* call.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// An error occurred while node is performing vote_* call.
    #[error(transparent)]
    Vote(#[from] VoteError),
    // Invalid parameters errors
    #[error(transparent)]
    InvalidParameters(#[from] InvalidParameters),
    // Invalid state errors
    #[error(transparent)]
    InvalidState(#[from] InvalidState),
    // Conversion errors
    #[error(transparent)]
    ConversionError(#[from] ConversionError),
    // Invalid state errors
    #[error(transparent)]
    InvalidThreshold(#[from] InvalidThreshold),
    // Invalid Candidate errors
    #[error(transparent)]
    InvalidCandidateSet(#[from] InvalidCandidateSet),
    // Key event errors
    #[error(transparent)]
    KeyEventError(#[from] KeyEventError),
    // Domain errors
    #[error(transparent)]
    DomainError(#[from] DomainError),
    // Tee errors
    #[error(transparent)]
    TeeError(#[from] TeeError),
    // Tee errors
    #[error(transparent)]
    NodeMigrationError(#[from] NodeMigrationError),
}

impl near_sdk::FunctionError for Error {
    fn panic(&self) -> ! {
        crate::env::panic_str(&self.to_string())
    }
}

impl From<TweakNotOnCurve> for PublicKeyError {
    fn from(_: TweakNotOnCurve) -> Self {
        Self::TweakNotOnCurve
    }
}

impl From<TweakNotOnCurve> for RespondError {
    fn from(_: TweakNotOnCurve) -> Self {
        Self::TweakNotOnCurve
    }
}
