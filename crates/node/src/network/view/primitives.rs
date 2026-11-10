mod adjacency_matrix;
mod live_network_connections;
mod measured_network_link;
mod network_view;

pub use adjacency_matrix::UnknownNodeError;
pub use measured_network_link::{
    LinkObservation, MeasuredNetworkLinkError, MeasuredNetworkLinks, NetworkLinkStatuses,
    ObserveLinkHealth, UpdateResult,
};

pub use live_network_connections::{LiveNetworkConnectionTrackerError, LiveNetworkConnections};
pub use network_view::{
    InferConnectionStatusFromLinkHealth, MeasuredNetworkConnectionsError,
    NetworkConnectionsHealthTracker,
};
