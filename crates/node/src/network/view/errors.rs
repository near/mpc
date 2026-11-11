use crate::network::view::primitives::{NodePairError, UnknownNodeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkViewUpdateError<N> {
    #[error("{0:?} is not a participant")]
    UnknownParticipant(N),
    #[error("message from {0:?} does not report its own block height")]
    OwnHeightMissing(N),
    #[error("a link needs two distinct participants, got {0:?} twice")]
    SelfLink(N),
}

impl<N> From<UnknownNodeError<N>> for NetworkViewUpdateError<N> {
    fn from(UnknownNodeError(node): UnknownNodeError<N>) -> Self {
        Self::UnknownParticipant(node)
    }
}

impl<N> From<NodePairError<N>> for NetworkViewUpdateError<N> {
    fn from(error: NodePairError<N>) -> Self {
        match error {
            NodePairError::UnknownNode(error) => error.into(),
            NodePairError::SameNode(node) => Self::SelfLink(node),
        }
    }
}
