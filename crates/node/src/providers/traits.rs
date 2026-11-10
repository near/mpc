use std::collections::BTreeSet;

pub trait CheckReadiness {
    type Node: Ord + Clone;

    /// Whether `nodes` can currently run a computation of `duration` together.
    /// Errors only if a node in `nodes` is not part of the network.
    fn check_readiness(
        &self,
        nodes: &BTreeSet<Self::Node>,
        duration: ComputationDuration,
    ) -> Result<(), NotReadyError<Self::Node>>;
}

#[derive(Clone, Copy)]
pub enum ComputationDuration {
    Any,
    Seconds,
    HalfMinute,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotReadyError<N> {
    #[error("node {0:?} is not in the network")]
    UnknownNode(N),
    #[error("nodes {a:?} and {b:?} are not connected")]
    NotConnected { a: N, b: N },
    #[error("connection between {a:?} and {b:?} is too degraded for this computation")]
    Degraded { a: N, b: N },
}
