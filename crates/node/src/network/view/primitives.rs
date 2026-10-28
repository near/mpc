mod adjacency_matrix;
mod measured_network_link;
mod network_view;

pub use network_view::{
    BrokenNetworkConnections, LinkEntry, LinkReport, MeasuredNetworkLinks, NetworkConnectionsView,
    NetworkConnectionsViewError, PreviousViewValidity,
};

pub use measured_network_link::{
    InferLinkStatus, LinkObservation, LinkStatus, MeasuredLink, RecentObservations,
};

pub use adjacency_matrix::AdjacencyMatrixError;
