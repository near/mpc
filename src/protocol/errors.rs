use crate::protocol::Participant;
use std::error;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ProtocolError {
    #[error("assertion failed {0}")]
    AssertionFailed(String),

    #[error("the ciphersuite does not support DKG")]
    DKGNotSupported,

    #[error("found empty polynomials or zero polynomial")]
    EmptyOrZeroCoefficients,

    #[error("could not extract the verification key from the commitment")]
    ErrorExtractVerificationKey,

    #[error("panicked while encoding an input.")]
    ErrorEncoding,

    #[error("the given bytes are not mappable to a scalar without modular reduction")]
    ErrorReducingBytesToScalar,

    #[error("encountered the identity element (identity point)")]
    IdentityElement,

    #[error("the sent commitment_hash does not equal the hash of the commitment")]
    InvalidCommitmentHash,

    #[error("invalid arguments for polynomial interpolation")]
    InvalidInterpolationArguments,

    #[error("incorrect number of commitments")]
    IncorrectNumberOfCommitments,

    #[error("the proof of knowledge of participant {0:?} is not valid")]
    InvalidProofOfKnowledge(Participant),

    #[error("participant {0:?} sent an invalid secret share")]
    InvalidSecretShare(Participant),

    #[error("the element you are trying to construct is malformed")]
    MalformedElement,

    #[error("detected a malicious participant {0:?}")]
    MaliciousParticipant(Participant),

    #[error("the constructed signing key is null")]
    MalformedSigningKey,

    #[error("the group element could not be serialized")]
    PointSerialization,

    #[error("encountered a zero scalar")]
    ZeroScalar,

    #[error("this should never happen, please report upstream")]
    Unreachable,

    // catch-all for foreign errors
    #[error("{0}")]
    Other(String),
}

impl From<Box<dyn error::Error + Send + Sync>> for ProtocolError {
    fn from(err: Box<dyn error::Error + Send + Sync>) -> Self {
        ProtocolError::Other(err.to_string())
    }
}

/// Represents an error which can happen when *initializing* a protocol.
///
/// These are related to bad parameters for the protocol, and things like that.
///
/// These are usually more recoverable than other protocol errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InitializationError {
    #[error("bad parameters: {0}")]
    BadParameters(String),

    #[error("participant list must contain {role}: {participant:?}")]
    MissingParticipant {
        role: &'static str,
        participant: Participant,
    },

    #[error("participant list cannot contain duplicates")]
    DuplicateParticipants,

    #[error("Participant count cannot be < 2, found: {participants}")]
    NotEnoughParticipants { participants: usize },

    #[error("not enough intersecting old/new participants ({participants}) to reconstruct private key for resharing with threshold bigger than old threshold ({threshold})")]
    NotEnoughParticipantsForThreshold {
        threshold: usize,
        participants: usize,
    },

    #[error("threshold {threshold} is too small, it must be at least {min}")]
    ThresholdTooSmall { threshold: usize, min: usize },

    #[error("threshold {threshold} is too large, it must be at most {max}")]
    ThresholdTooLarge { threshold: usize, max: usize },

    #[error("participant has an invalid index")]
    InvalidParticipantIndex,
}
