use near_sdk::Gas;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("Signature request has timed out.")]
    Timeout,
    #[error("Signature request has already been submitted. Please, try again later.")]
    PayloadCollision,
    #[error("Payload hash cannot be convereted to Scalar.")]
    PayloadMalform,
    #[error("Contract version is greater than allowed.")]
    VersionTooHigh,
    #[error("Attached deposit is lower than required. Attached: {0}, required: {1}.")]
    DepositInsufficient(u128, u128),
    #[error("Provided gas is lower than required: Provided: {0}, required {1}.")]
    GasInsufficient(Gas, Gas),
    #[error("Too many pending requests. Please, try again later.")]
    RequestLimitExceeded,
    #[error("This sign request was removed from pending requests: timed out or completed.")]
    RequestNotInPending,
}

#[derive(Debug, thiserror::Error)]
pub enum RespondError {
    #[error("This sign request was removed from pending requests: timed out or completed.")]
    RequestNotInPending,
    #[error("Signature could not be verified.")]
    SignatureNotVerified,
    #[error("Protocol state is not running.")]
    ProtocolStateNotRunning,
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("Protocol state is not running")]
    ProtocolStateNotRunning,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Protocol state is not running or resharing.")]
    ProtocolStateNotRunningOrResharing,
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("Threshold cannot be greater than the number of candidates")]
    ThresholdTooHigh,
}

#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not not in the participant set.")]
    VoterNotParticipant,
    #[error("Account to be kicked is not not in the participant set.")]
    KickNotParticipant,
    #[error("Account to join is not not in the candidates set.")]
    JoinNotCandidate,
    #[error("Account to join is already in the participant set.")]
    JoinAlreadyParticipant,
    #[error("Mismatched epoch.")]
    MismatchedEpoch,
    #[error("Number of participants cannot go below threshold.")]
    ParticipantsBelowThreshold,
    #[error("Protocol state is not the expected: {0}")]
    ProtocolStateNotExpected(String),
}

#[derive(Debug, thiserror::Error)]
pub enum MpcContractError {
    #[error("sign fn error: {0}")]
    SignError(SignError),
    #[error("respond fn error: {0}")]
    RespondError(RespondError),
    #[error("vote_* fn error: {0}")]
    VoteError(VoteError),
    #[error("init fn error: {0}")]
    InitError(InitError),
    #[error("join fn error: {0}")]
    JoinError(JoinError),
    #[error("public_key fn error: {0}")]
    PublicKeyError(PublicKeyError),
}

impl near_sdk::FunctionError for MpcContractError {
    fn panic(&self) -> ! {
        crate::env::panic_str(&self.to_string())
    }
}
