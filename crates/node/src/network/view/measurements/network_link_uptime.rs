////! Link measurement that tracks presence only: observations carry nothing, so a link's status is
////! the `since` and `downs` of its [`LinkStatus`](super::primitives::LinkStatus). An alternative to
////! [`NetworkConnectionsBlockLatency`](super::network_link_latency::NetworkConnectionsBlockLatency),
////! which also tracks lag; the wiring picks one.
//
//use std::collections::BTreeMap;
//
//use near_mpc_bounded_collections::NonEmptyBTreeSet;
//use near_time::Instant;
//
//use crate::{
//    network::view::{
//        first_hand_indexer_heights::FirstHandIndexerHeights,
//        primitives::{
//            ConnectionStatus, GradeLink, LinkObservation, LinkReport, MeasuredNetworkConnections,
//            PreviousViewValidity, Uptime, UsableNetworkConnections,
//        },
//        view_manager::{LocalPeerReport, MeasureNetworkConnections, NetworkViewUpdateError},
//    },
//    primitives::ParticipantId,
//};
//
///// Connections judged by presence alone: a `reporter` lists a peer only while connected to it
///// both ways, so listing is the observation and heights are not looked at.
//pub struct NetworkConnectionsUptime {
//    connections: MeasuredNetworkConnections<ParticipantId, ()>,
//}
//
//impl NetworkConnectionsUptime {
//    pub fn new(participants: &NonEmptyBTreeSet<ParticipantId>) -> Self {
//        Self {
//            connections: MeasuredNetworkConnections::new(participants, ()),
//        }
//    }
//}
//
//impl MeasureNetworkConnections for NetworkConnectionsUptime {
//    type Link = ();
//
//    fn record_report(
//        &mut self,
//        report: &LocalPeerReport,
//        first_hand_heights: &FirstHandIndexerHeights,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, NetworkViewUpdateError> {
//        let observations: BTreeMap<_, _> = first_hand_heights
//            .iter()
//            .map(|(origin, _)| origin)
//            .filter(|origin| **origin != report.reporter)
//            .map(|origin| {
//                let observation = if report.peers.contains_key(origin) {
//                    LinkObservation::Present(())
//                } else {
//                    LinkObservation::Absent
//                };
//                (*origin, observation)
//            })
//            .collect();
//        Ok(self
//            .connections
//            .record_observations_from(&report.reporter, observations, now)?)
//    }
//
//    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, ()> {
//        self.connections.link_report(now)
//    }
//
//    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId> {
//        self.connections.usable_connections()
//    }
//}
//
///// Nothing is measured, so an up link is as good as its uptime.
//impl GradeLink for () {
//    fn grade(&self, uptime: Uptime) -> ConnectionStatus {
//        ConnectionStatus::Live(uptime)
//    }
//}
