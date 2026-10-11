use std::time::Duration;

use crate::views::deserialize::DeserializationError;

#[derive(Clone, Debug, thiserror::Error, PartialEq)]
pub enum TransportError<C> {
    #[error("failed to deserialize contract response: {0}")]
    Deserialization(#[source] DeserializationError),
    #[error("contract view call failed: {0}")]
    View(#[source] C),
    #[error("view client closed monitoring")]
    MonitoringClosed,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq)]
pub enum WaitError<C> {
    #[error("predicate not satisfied within {0:?}")]
    TimedOut(Duration),
    #[error(transparent)]
    Transport(#[from] TransportError<C>),
}
