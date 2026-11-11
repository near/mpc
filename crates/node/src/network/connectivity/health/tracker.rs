use near_time::Instant;

use crate::network::connectivity::{
    graph::UnknownNodeError,
    health::{
        connections::{ConnectionChanged, EstablishedConnections, InferredConnection},
        links::{LinkMeasurements, LinkObservation, LinkStatusChange, UpdateLinkStatus},
    },
};

pub struct ConnectionTracker<N, C, L> {
    // a link is a directed connection node A --> B,
    // each link is measured, such that we can infer link quality from the measurements.
    link_measurements: LinkMeasurements<N, L>,
    // a connection between two nodes is as good as the worse of the two links between them
    established_connections: EstablishedConnections<N, C>,
}

impl<N: Ord + Clone, C, L> ConnectionTracker<N, C, L> {
    pub fn update_with_observation<O>(
        &mut self,
        observation: LinkObservation<N, O>,
        now: Instant,
    ) -> Result<ConnectionChanged, UnknownNodeError<N>>
    where
        L: UpdateLinkStatus<O>,
        L::LinkStatus: InferConnection<ConnectionStatus = C>,
        C: PartialEq,
    {
        let LinkObservation { link, observation } = observation;
        let status_change = self
            .link_measurements
            .record_observation(&link, observation, now)?;
        match status_change {
            LinkStatusChange::Unchanged => Ok(ConnectionChanged::No),
            LinkStatusChange::Changed(new_status) => {
                let other_direction = self.link_measurements.status(&link.reversed())?;
                let inferred_connection =
                    L::LinkStatus::infer_connection(Some(new_status), other_direction);
                self.established_connections
                    .update_connection(&link.into(), inferred_connection)
            }
        }
    }
}

/// Implemented by a link status type.
pub trait InferConnection: Sized {
    type ConnectionStatus;
    /// The connection that the two links between a pair of nodes add up to. A link is `None`
    /// while it has no observations.
    fn infer_connection(
        a: Option<Self>,
        b: Option<Self>,
    ) -> InferredConnection<Self::ConnectionStatus>;
}

// todo tests
