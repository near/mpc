use near_time::Instant;

use crate::network::view::primitives::{
    LinkObservation,
    errors::UnknownNodeError,
    live_network_connections::{InferredConnection, LiveNetworkConnections},
    measured_network_link::{MeasuredNetworkLinks, ObserveLinkHealth, UpdateResult},
};

pub struct NetworkConnectionsHealthTracker<N, C, L> {
    // a link is a directed connection node A --> B,
    // each link is measured, such that we can infer link quality from the measurements.
    measured_links: MeasuredNetworkLinks<N, L>,
    // a connection between two nodes is as good as the worse of the two links between them
    connection_status: LiveNetworkConnections<N, C>,
}
impl<N: Ord + Clone, C, L, O> NetworkConnectionsHealthTracker<N, C, L>
where
    N: Ord + Clone,
    L: ObserveLinkHealth<Observation = O, ConnectionStatus = C>,
    C: PartialEq + Clone,
{
    pub fn update_with_observation(
        &mut self,
        observation: LinkObservation<N, O>,
        now: Instant,
    ) -> Result<UpdateResult<InferredConnection<C>>, UnknownNodeError<N>> {
        let LinkObservation { link, observation } = observation;
        let update_result = self
            .measured_links
            .record_observation(&link, observation, now)?;
        match update_result {
            UpdateResult::StatusRemained => Ok(UpdateResult::StatusRemained),
            UpdateResult::StatusChanged(new_status) => {
                let other_direction = self.measured_links.status(&link.reversed())?;
                let connection_satus =
                    L::infer_connection_status(Some(new_status), other_direction);
                self.connection_status
                    .update_connection(&link.into(), connection_satus)
            }
        }
    }
}

//pub trait ReportConnectionHealth {
//    fn update_with(
//        &mut self,
//        a: Self::LinkStatus,
//        b: Self::LinkStatus,
//    ) -> ConnectionHealthUpdateResult;
//}

//pub enum ConnectionHealthUpdateResult {
//    Changed,
//    DidNotChange,
//}

//impl<N: Ord + Clone> UsableNetworkConnections<N> {
//    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
//        Self {
//            connections: AdjacencyMatrix::complete(nodes, ConnectionStatus::Unknown),
//        }
//    }
//
//    pub fn are_connected(&self, a: &N, b: &N, required_uptime: Uptime) -> bool {
//        matches!(self.connections.edge(a, b), Ok(Some(status)) if status.satisfies(required_uptime))
//    }
//
//    pub fn usable_from(
//        &self,
//        node: &N,
//        required_uptime: Uptime,
//    ) -> Result<BTreeSet<N>, AdjacencyMatrixError<N>> {
//        Ok(self
//            .connections
//            .edges_from(node)?
//            .filter(|(_, status)| status.satisfies(required_uptime))
//            .map(|(peer, _)| peer.clone())
//            .collect())
//    }
//

//
//#[derive(Debug, Clone, Copy, PartialEq, Eq)]
//pub enum PreviousViewValidity {
//    Superseded,
//    Valid,
//}
//
//impl<N: Ord + Clone, S: GradeLink> MeasuredNetworkConnections<N, S> {
//    /// Records the `reporter`'s observations and updates the status for all connections of
//    /// `reporter`.
//    /// Returns [`PreviousViewValidity::Superseded`] in case a connection changed status (e.g. one
//    /// that used to be online is now broken, or vice-versa).
//    /// Errors if the `reporter` observes itself or an unknown node.
//    pub fn record_observations_from<T>(
//        &mut self,
//        reporter: &N,
//        observations: BTreeMap<N, LinkObservation<T>>,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>>
//    where
//        S: Clone + Extend<T>,
//    {
//        let mut validity = PreviousViewValidity::Valid;
//        for (origin, observation) in observations {
//            if self.record_link_observation(&origin, reporter, observation, now)?
//                == PreviousViewValidity::Superseded
//            {
//                validity = PreviousViewValidity::Superseded;
//            }
//        }
//        Ok(validity)
//    }
//
//    fn record_link_observation<T>(
//        &mut self,
//        origin: &N,
//        receiver: &N,
//        observation: LinkObservation<T>,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>>
//    where
//        S: Clone + Extend<T>,
//    {
//        self.measured_links
//            .record_observation(origin, receiver, observation, now)?;
//        self.refresh_connection_status(origin, receiver, now)
//    }
//
//    /// The read-only snapshot for readers.
//    pub fn usable_connections(&self) -> UsableNetworkConnections<N> {
//        self.connections.clone()
//    }
//
//    /// errors if from == to or if the nodes are not in the graph
//    fn refresh_connection_status(
//        &mut self,
//        a: &N,
//        b: &N,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
//        let status = |link: Option<&LinkStatus<S>>| {
//            link.map_or(ConnectionStatus::Unknown, |link| {
//                link.connection_status(now)
//            })
//        };
//        let a_to_b = status(self.measured_links.link_status(a, b)?);
//        let b_to_a = status(self.measured_links.link_status(b, a)?);
//        self.connections.set(a, b, a_to_b.min(b_to_a))
//    }
//
//    pub fn link_report(&self, now: Instant) -> LinkReport<N, S>
//    where
//        S: Clone,
//    {
//        self.measured_links.report(now)
//    }
//}
//
///// Uninterrupted presence a computation requires of a connection.
/////
///// The tiers mirror today's consumers, signatures finishing within seconds and triple generation
///// within half a minute, and sit in this generic layer only to keep the connection matrix free of
///// a type parameter. Refactor or replace them when the consumers' needs change.
//#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
//pub enum Uptime {
//    Any,
//    Seconds,
//    HalfMinute,
//}
//
//impl Uptime {
//    /// The highest tier an uninterrupted presence of `up_for` satisfies.
//    pub fn exceeds(up_for: Duration) -> Self {
//        if up_for >= UPTIME_HALF_MINUTE {
//            Self::HalfMinute
//        } else if up_for >= UPTIME_SECONDS {
//            Self::Seconds
//        } else {
//            Self::Any
//        }
//    }
//}
//
///// Grades an up link: the measurement may demote it below `Live(uptime)`.
//pub trait GradeLink {
//    fn grade(&self, uptime: Uptime) -> ConnectionStatus;
//}
//
//impl<S: GradeLink> LinkStatus<S> {
//    /// A link that never went down is not held to `since`: it may have been up long before we
//    /// observed it.
//    pub fn connection_status(&self, now: Instant) -> ConnectionStatus {
//        match self {
//            Self::Down { .. } => ConnectionStatus::Broken,
//            Self::Up {
//                downs: 0, status, ..
//            } => status.grade(Uptime::HalfMinute),
//            Self::Up { since, status, .. } => {
//                status.grade(Uptime::exceeds(now.signed_duration_since(*since)))
//            }
//        }
//    }
//}
//
///// Ordered worst to best, so a pair's status is the `min` of its two directions.
//#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
//pub enum ConnectionStatus<S> {
//    Broken,
//    Live(S),
//    Unknown,
//}
//
//
//impl<S> ConnectionSufficentFor for ConnectionStatus<S>
//where
//    S: ConnectionSufficentFor,
//{
//    fn connection_sufficient_for(&self, duration: ComputationDuration) -> bool {
//        match self {
//            ConnectionStatus::Broken => false,
//            ConnectionStatus::Live(status) => status.connection_sufficient_for(duration),
//            ConnectionStatus::Unknown => true,
//        }
//    }
//}
//
//impl<N: Ord + Clone, S> MeasuredNetworkConnections<N, S> {
//    /// A view over `nodes` with no observations yet; `unmeasured` is what a link's measurement
//    /// starts from each time it comes up.
//    ///
//    /// Panics if there are more nodes than `NodeIndex` can address (65,535).
//    pub fn new(nodes: &NonEmptyBTreeSet<N>, unmeasured: S) -> Self {
//        let measured_links = MeasuredNetworkLinks::new(nodes, unmeasured);
//        let connections = UsableNetworkConnections::new(nodes);
//        Self {
//            measured_links,
//            connections,
//        }
//    }
//}

//// Every directed link's [`LinkStatus`], stored as an adjacency matrix.
//impl<N: Ord + Clone, S> MeasuredNetworkLinks<N, S> {
//    pub fn report(&self, now: Instant) -> LinkReport<N, S>
//    where
//        S: Clone,
//    {
//        LinkReport {
//            taken_at: now,
//            links: self
//                .measured_network_links
//                .edges()
//                .map(|(from, to, status)| LinkEntry {
//                    from: from.clone(),
//                    to: to.clone(),
//                    status: status.clone(),
//                })
//                .collect(),
//        }
//    }
//}

///// Every measured link's current status, sampled at one point in time.
///// Links with no observations yet are not included.
//#[derive(Debug, Clone)]
//pub struct LinkReport<N, S> {
//    pub taken_at: Instant,
//    pub links: Vec<LinkEntry<N, S>>,
//}

//#[derive(Debug, Clone)]
//pub struct LinkEntry<N, S> {
//    pub from: N,
//    pub to: N,
//    pub status: LinkStatus<S>,
//}

//
//impl<N: Ord + Clone> UsableNetworkConnections<N> {
//    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
//        Self {
//            connections: AdjacencyMatrix::complete(nodes, ConnectionStatus::Unknown),
//        }
//    }
//
//    pub fn are_connected(&self, a: &N, b: &N, required_uptime: Uptime) -> bool {
//        matches!(self.connections.edge(a, b), Ok(Some(status)) if status.satisfies(required_uptime))
//    }
//
//    pub fn usable_from(
//        &self,
//        node: &N,
//        required_uptime: Uptime,
//    ) -> Result<BTreeSet<N>, AdjacencyMatrixError<N>> {
//        Ok(self
//            .connections
//            .edges_from(node)?
//            .filter(|(_, status)| status.satisfies(required_uptime))
//            .map(|(peer, _)| peer.clone())
//            .collect())
//    }
//
//    pub fn can_compute_with(
//        &self,
//        nodes: &BTreeSet<N>,
//        required_uptime: Uptime,
//    ) -> Result<(), MeasuredNetworkConnectionsError<N>> {
//        let unusable = |status: Option<&ConnectionStatus>| {
//            !status.is_some_and(|status| status.satisfies(required_uptime))
//        };
//        match self.connections.find_pair_within(nodes, unusable)? {
//            None => Ok(()),
//            Some((p, q)) => Err(MeasuredNetworkConnectionsError::BrokenConnection(
//                p.clone(),
//                q.clone(),
//            )),
//        }
//    }
//
//    fn set(
//        &mut self,
//        a: &N,
//        b: &N,
//        status: ConnectionStatus,
//    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
//        let previous = self.connections.set_edge(a, b, status)?;
//        if previous == Some(status) {
//            Ok(PreviousViewValidity::Valid)
//        } else {
//            Ok(PreviousViewValidity::Superseded)
//        }
//    }
//}

// todo tests
