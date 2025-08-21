#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeQuoteStatus {
    /// No TEE information was found for this participant.
    /// This indicates the participant is not running in a TEE environment
    /// or has not provided TEE attestation data.
    None,

    /// TEE quote and Docker image verification both passed successfully.
    /// The participant is considered to have a valid, verified TEE status.
    Valid,

    /// TEE verification failed - either the quote verification failed,
    /// the Docker image verification failed, or both validations failed.
    /// The participant should not be trusted for TEE-dependent operations.
    Invalid,
}
