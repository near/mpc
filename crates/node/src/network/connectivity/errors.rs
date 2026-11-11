use crate::network::connectivity::graph::UnknownNodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerReportError<N> {
    #[error("{0:?} is not a participant")]
    UnknownParticipant(N),
    #[error("message from {0:?} does not report its own block height")]
    OwnHeightMissing(N),
}

impl<N> From<UnknownNodeError<N>> for PeerReportError<N> {
    fn from(UnknownNodeError(node): UnknownNodeError<N>) -> Self {
        Self::UnknownParticipant(node)
    }
}
