//! Link measurement that tracks presence only: for how long a link has been present without
//! interruption. An alternative to
//! [`NetworkConnectionsBlockLatency`](super::network_link_latency::NetworkConnectionsBlockLatency),
//! which also tracks lag; the wiring picks one.

use std::{collections::BTreeMap, num::NonZeroUsize};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Duration, Instant};
use time::ext::InstantExt as _;

use crate::{
    network::{
        constants::{UPTIME_HALF_MINUTE, UPTIME_SECONDS},
        view::{
            first_hand_indexer_heights::FirstHandIndexerHeights,
            primitives::{
                GradeLink, InferLinkStatus, LinkObservation, LinkReport, LinkSpeed, LinkStatus,
                MeasuredNetworkConnections, PreviousViewValidity, RecentObservations, Uptime,
                UsableNetworkConnections,
            },
            view_manager::{LocalPeerReport, MeasureNetworkConnections, NetworkViewUpdateError},
        },
    },
    primitives::ParticipantId,
};

/// Connections judged by presence alone: a `reporter` lists a peer only while connected to it
/// both ways, so listing is the observation and heights are not looked at.
pub struct NetworkConnectionsUptime {
    connections: MeasuredNetworkConnections<ParticipantId, LinkUptime, ()>,
}

impl NetworkConnectionsUptime {
    pub fn new(
        participants: &NonEmptyBTreeSet<ParticipantId>,
        measurement_window: NonZeroUsize,
    ) -> Self {
        Self {
            connections: MeasuredNetworkConnections::new(participants, measurement_window),
        }
    }
}

impl MeasureNetworkConnections for NetworkConnectionsUptime {
    type Link = LinkUptime;

    fn record_report(
        &mut self,
        report: &LocalPeerReport,
        first_hand_heights: &FirstHandIndexerHeights,
        now: Instant,
    ) -> Result<PreviousViewValidity, NetworkViewUpdateError> {
        let observations: BTreeMap<_, _> = first_hand_heights
            .iter()
            .map(|(origin, _)| origin)
            .filter(|origin| **origin != report.reporter)
            .map(|origin| {
                let observation = if report.peers.contains_key(origin) {
                    LinkObservation::Present(())
                } else {
                    LinkObservation::Absent
                };
                (*origin, observation)
            })
            .collect();
        Ok(self
            .connections
            .record_observations_from(&report.reporter, observations, now)?)
    }

    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, LinkUptime> {
        self.connections.link_report(now)
    }

    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId> {
        self.connections.usable_connections()
    }
}

/// For how long the link has been present without interruption: from the first present sample
/// after the last absent one to the newest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkUptime {
    pub up_for: Duration,
}

impl<T> InferLinkStatus<T> for LinkUptime {
    fn infer_link_status(obs: &RecentObservations<T>) -> LinkStatus<Self> {
        let newest = obs.newest();
        if newest.present().is_none() {
            return LinkStatus::Absent;
        }
        let up_since = obs
            .newest_first()
            .take_while(|observation| observation.present().is_some())
            .last()
            .map_or(newest.at, |observation| observation.at);
        LinkStatus::Present(LinkUptime {
            up_for: newest.at.signed_duration_since(up_since),
        })
    }
}

impl GradeLink for LinkUptime {
    fn grade(&self) -> LinkSpeed {
        LinkSpeed::Up(uptime_reached(self.up_for))
    }
}

/// The highest [`Uptime`] an uninterrupted presence of `up_for` satisfies.
pub fn uptime_reached(up_for: Duration) -> Uptime {
    if up_for >= UPTIME_HALF_MINUTE {
        Uptime::HalfMinute
    } else if up_for >= UPTIME_SECONDS {
        Uptime::Seconds
    } else {
        Uptime::Any
    }
}
