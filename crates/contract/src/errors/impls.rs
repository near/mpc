use std::fmt;

use crate::crypto_shared::kdf::TweakNotOnCurve;

use super::{
    ConversionError, DomainError, Error, ErrorKind, InvalidCandidateSet, InvalidParameters,
    InvalidState, InvalidThreshold, KeyEventError, NodeMigrationError, PublicKeyError,
    RespondError, SignError, TeeError, VoteError,
};

impl Error {
    /// Returns the corresponding [`ErrorKind`] for this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<SignError> for Error {
    fn from(code: SignError) -> Self {
        Self(ErrorKind::Sign(code))
    }
}

impl From<RespondError> for Error {
    fn from(code: RespondError) -> Self {
        Self(ErrorKind::Respond(code))
    }
}

impl From<PublicKeyError> for Error {
    fn from(code: PublicKeyError) -> Self {
        Self(ErrorKind::PublicKey(code))
    }
}

impl From<VoteError> for Error {
    fn from(code: VoteError) -> Self {
        Self(ErrorKind::Vote(code))
    }
}

impl From<InvalidParameters> for Error {
    fn from(code: InvalidParameters) -> Self {
        Self(ErrorKind::InvalidParameters(code))
    }
}

impl From<NodeMigrationError> for Error {
    fn from(code: NodeMigrationError) -> Self {
        Self(ErrorKind::NodeMigrationError(code))
    }
}

impl From<InvalidState> for Error {
    fn from(code: InvalidState) -> Self {
        Self(ErrorKind::InvalidState(code))
    }
}

impl From<ConversionError> for Error {
    fn from(code: ConversionError) -> Self {
        Self(ErrorKind::ConversionError(code))
    }
}

impl From<KeyEventError> for Error {
    fn from(code: KeyEventError) -> Self {
        Self(ErrorKind::KeyEventError(code))
    }
}

impl From<TeeError> for Error {
    fn from(code: TeeError) -> Self {
        Self(ErrorKind::TeeError(code))
    }
}

impl From<InvalidThreshold> for Error {
    fn from(code: InvalidThreshold) -> Self {
        Self(ErrorKind::InvalidThreshold(code))
    }
}

impl From<InvalidCandidateSet> for Error {
    fn from(code: InvalidCandidateSet) -> Self {
        Self(ErrorKind::InvalidCandidateSet(code))
    }
}

impl From<DomainError> for Error {
    fn from(code: DomainError) -> Self {
        Self(ErrorKind::DomainError(code))
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
