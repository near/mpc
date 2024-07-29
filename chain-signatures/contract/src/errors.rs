use near_sdk::Gas;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("Signature request has timed out.")]
    Timeout,
    #[error("Signature request has already been submitted. Please try again later.")]
    PayloadCollision,
    #[error("Malformed payload: {0}")]
    MalformedPayload(String),
    #[error(
        "This key version is not supported. Call latest_key_version() to get the latest supported version."
    )]
    UnsupportedKeyVersion,
    #[error("Attached deposit is lower than required. Attached: {0}, Required: {1}.")]
    InsufficientDeposit(u128, u128),
    #[error("Provided gas is lower than required. Provided: {0}, required {1}.")]
    InsufficientGas(Gas, Gas),
    #[error("Too many pending requests. Please try again later.")]
    RequestLimitExceeded,
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespondError {
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
    #[error("The provided signature is invalid.")]
    InvalidSignature,
    #[error("The protocol is not Running.")]
    ProtocolNotInRunningState,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum JoinError {
    #[error("The protocol is not Running.")]
    ProtocolStateNotRunning,
    #[error("Account to join is already in the participant set.")]
    JoinAlreadyParticipant,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Protocol state is not running or resharing.")]
    ProtocolStateNotRunningOrResharing,
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InitError {
    #[error("Threshold cannot be greater than the number of candidates")]
    ThresholdTooHigh,
    #[error("Cannot load in contract due to missing state")]
    ContractStateIsMissing,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not in the participant set.")]
    VoterNotParticipant,
    #[error("Account to be kicked is not in the participant set.")]
    KickNotParticipant,
    #[error("Account to join is not in the candidate set.")]
    JoinNotCandidate,
    #[error("Mismatched epoch.")]
    EpochMismatch,
    #[error("Number of participants cannot go below threshold.")]
    ParticipantsBelowThreshold,
    #[error("Update not found.")]
    UpdateNotFound,
    #[error("Attached deposit is lower than required. Attached: {0}, Required: {1}.")]
    InsufficientDeposit(u128, u128),
    #[error("Unexpected protocol state: {0}")]
    UnexpectedProtocolState(String),
    #[error("Unexpected: {0}")]
    Unexpected(String),
}

/// A list specifying general categories of MPC Contract errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An error occurred while user is performing sign request.
    #[error("sign error {0}")]
    Sign(#[from] SignError),
    /// An error occurred while node is performing respond call.
    #[error("respond error {0}")]
    Respond(#[from] RespondError),
    /// An error occurred while node is performing join call.
    #[error("{0}")]
    Join(#[from] JoinError),
    /// An error occurred while user is performing public_key_* call.
    #[error("{0}")]
    PublicKey(#[from] PublicKeyError),
    /// An error occurred while developer is performing init_* call.
    #[error("{0}")]
    Init(#[from] InitError),
    /// An error occurred while node is performing vote_* call.
    #[error("{0}")]
    Vote(#[from] VoteError),
    // TODO: remove if not used, check if some of the errors needs to be moved here
    /// An error from performing IO.
    #[error("IO")]
    Io,
    /// An error from converting data.
    #[error("DataConversion")]
    DataConversion,
    /// An error that cannot be categorized into the other error kinds.
    #[error("Other")]
    Other,
}

impl near_sdk::FunctionError for Error {
    fn panic(&self) -> ! {
        crate::env::panic_str(&self.to_string())
    }
}
