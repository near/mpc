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
