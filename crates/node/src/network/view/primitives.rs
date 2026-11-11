mod adjacency_matrix;
mod edge;
mod errors;
mod live_network_connections;
mod measured_network_link;
mod network_view;

pub use edge::{DirectedEdge, UndirectedEdge};
pub use errors::UnknownNodeError;
pub use live_network_connections::{
    ConnectionChanged, InferredConnection, LiveNetworkConnections,
};
pub use measured_network_link::{
    InferConnectionStatus, LinkObservation, MeasuredNetworkLinks, NetworkLinkStatuses,
    ReportLinkStatus, UpdateLinkStatus, UpdateResult,
};
pub use network_view::NetworkConnectionsHealthTracker;
