#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("node {0:?} is not in the network graph")]
pub struct UnknownNodeError<N>(pub N);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected two distinct nodes, got {0:?} twice")]
pub struct SameNodeError<N>(pub N);
