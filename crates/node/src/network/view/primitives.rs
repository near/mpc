mod adjacency_matrix;
mod errors;
mod live_network_connections;
mod measured_network_link;
mod network_view;

pub use errors::{NodePairError, UnknownNodeError};
pub use live_network_connections::LiveNetworkConnections;
pub use measured_network_link::{
    LinkObservation, MeasuredNetworkLinks, NetworkLinkStatuses, ObserveLinkHealth, UpdateResult,
};
pub use network_view::{InferConnectionStatusFromLinkHealth, NetworkConnectionsHealthTracker};
