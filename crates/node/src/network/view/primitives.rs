mod adjacency_matrix;
mod measured_network_connections;
mod measured_network_link;

pub use measured_network_connections::{
    ConnectionStatus, GradeLink, LinkEntry, LinkReport, LinkSpeed, MeasuredNetworkConnections,
    MeasuredNetworkConnectionsError, MeasuredNetworkLinks, PreviousViewValidity, Uptime,
    UsableNetworkConnections,
};

pub use measured_network_link::{
    InferLinkStatus, LinkObservation, LinkStatus, MeasuredLink, RecentObservations,
    TimedObservation,
};

pub use adjacency_matrix::AdjacencyMatrixError;
