use std::{
    collections::{BTreeMap, BTreeSet},
    hash::Hash,
    sync::Arc,
};

use futures::future::join_all;
use near_block_primitives::BlockCount;
use near_time::{Clock, Duration};
use tokio::sync::watch;

use crate::{
    network::{
        connectivity::{
            CheckComputationSupport, EstablishedConnections,
            first_hand_indexer_heights::{FirstHandIndexerHeights, ReportedIndexerHeight},
        },
        readiness::NetworkReadiness,
    },
    providers::participant_selection::ComputationDuration,
};

/// Derives the [`NetworkReadiness`] for computations of each subscribed [`ComputationDuration`]
/// from the connections and first-hand indexer heights.
/// Publishes whenever the connections change and on every `publish_interval`.
pub(super) struct NetworkReadinessPublisher<N, S> {
    me: N,
    max_indexer_height_lag: BlockCount,
    publish_interval: Duration,
    clock: Clock,
    connections: watch::Receiver<Arc<EstablishedConnections<N, S>>>,
    heights: watch::Receiver<FirstHandIndexerHeights<N>>,
    readiness: BTreeMap<ComputationDuration, watch::Sender<NetworkReadiness<N>>>,
}

impl<N, S> NetworkReadinessPublisher<N, S>
where
    N: Ord + Hash + Clone,
    S: CheckComputationSupport,
{
    fn new(
        me: N,
        max_indexer_height_lag: BlockCount,
        publish_interval: Duration,
        clock: Clock,
        connections: watch::Receiver<Arc<EstablishedConnections<N, S>>>,
        heights: watch::Receiver<FirstHandIndexerHeights<N>>,
    ) -> Self {
        Self {
            me,
            max_indexer_height_lag,
            publish_interval,
            clock,
            connections,
            heights,
            readiness: BTreeMap::new(),
        }
    }

    pub(super) fn subscribe(
        &mut self,
        duration: ComputationDuration,
    ) -> watch::Receiver<NetworkReadiness<N>> {
        self.readiness.entry(duration).or_default().subscribe()
    }

    /// Publishes at once, then again when a connection changes, and every `publish_interval` to
    /// pick up the indexer heights and what the passing of time changes. The heights are not a
    /// wake-up source: they change with every report. Runs until the monitor is gone or nothing
    /// reads the results any more.
    async fn run(mut self) {
        let durations: BTreeSet<_> = self.readiness.keys().copied().collect();
        loop {
            self.publish(&durations);
            tokio::select! {
                changed = self.connections.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = join_all(self.readiness.values().map(|sender| sender.closed())) => return,
                _ = self.clock.sleep(self.publish_interval) => {}
            }
        }
    }

    fn publish(&self, durations: &BTreeSet<ComputationDuration>) {
        let alive = alive_participants(
            &self.me,
            &self.heights.borrow(),
            self.max_indexer_height_lag,
        );
        let not_supporting = self
            .connections
            .borrow()
            .connections_not_supporting(durations, self.clock.now());
        for (duration, broken_connections) in not_supporting {
            let Some(sender) = self.readiness.get(&duration) else {
                continue;
            };
            let readiness = NetworkReadiness::new(alive.clone(), broken_connections);
            sender.send_if_modified(|published| {
                if *published == readiness {
                    return false;
                }
                *published = readiness;
                true
            });
        }
    }
}

/// The participants whose first-hand indexer height is at most `max_lag` blocks behind `me`'s.
fn alive_participants<N: Ord + Clone>(
    me: &N,
    heights: &FirstHandIndexerHeights<N>,
    max_lag: BlockCount,
) -> BTreeSet<N> {
    let my_height = heights
        .iter()
        .find_map(|(participant, height)| (participant == me).then_some(*height))
        .unwrap_or(ReportedIndexerHeight::Unknown);
    heights
        .iter()
        .filter(|(_, height)| !is_behind(my_height, **height, max_lag))
        .map(|(participant, _)| participant.clone())
        .collect()
}

/// An unknown own height disables the check; an unknown peer height fails it.
fn is_behind(
    my_height: ReportedIndexerHeight,
    peer_height: ReportedIndexerHeight,
    max_lag: BlockCount,
) -> bool {
    match (my_height, peer_height) {
        (ReportedIndexerHeight::Unknown, _) => false,
        (ReportedIndexerHeight::Known(_), ReportedIndexerHeight::Unknown) => true,
        (ReportedIndexerHeight::Known(mine), ReportedIndexerHeight::Known(peer)) => {
            mine.blocks_since(peer).is_some_and(|lag| lag > max_lag)
        }
    }
}
