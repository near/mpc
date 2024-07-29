use std::borrow::Cow;
use std::fmt;

use super::{
    Error, ErrorKind, ErrorRepr, InitError, JoinError, PublicKeyError, RespondError, SignError,
    VoteError,
};

impl Error {
    /// Construct a workspaces [`Error`] with the details of an error which includes
    /// the custom error message with further context and the [`ErrorKind`] that
    /// represents the category of error.
    pub fn message<T>(kind: ErrorKind, msg: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        Self {
            repr: ErrorRepr::Message {
                kind,
                message: msg.into(),
            },
        }
    }

    /// Construct a workspaces [`Error`] with the details of an error which only
    /// includes the [`ErrorKind`] that represents the category of error.
    pub fn simple(kind: ErrorKind) -> Self {
        Self {
            repr: ErrorRepr::Simple(kind),
        }
    }

    /// Returns the corresponding [`ErrorKind`] for this error.
    pub fn kind(&self) -> &ErrorKind {
        match &self.repr {
            ErrorRepr::Simple(kind) => kind,
            ErrorRepr::Message { kind, .. } => kind,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.repr)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.repr.source()
    }
}

impl From<SignError> for Error {
    fn from(code: SignError) -> Self {
        Self::simple(ErrorKind::Sign(code))
    }
}

impl From<RespondError> for Error {
    fn from(code: RespondError) -> Self {
        Self::simple(ErrorKind::Respond(code))
    }
}

impl From<JoinError> for Error {
    fn from(code: JoinError) -> Self {
        Self::simple(ErrorKind::Join(code))
    }
}

impl From<PublicKeyError> for Error {
    fn from(code: PublicKeyError) -> Self {
        Self::simple(ErrorKind::PublicKey(code))
    }
}

impl From<InitError> for Error {
    fn from(code: InitError) -> Self {
        Self::simple(ErrorKind::Init(code))
    }
}

impl From<VoteError> for Error {
    fn from(code: VoteError) -> Self {
        Self::simple(ErrorKind::Vote(code))
    }
}
