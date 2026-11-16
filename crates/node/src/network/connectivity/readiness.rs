use std::{collections::BTreeSet, hash::Hash, sync::Arc};

use near_block_primitives::BlockCount;
use near_time::{Clock, Duration, Instant};
use tokio::sync::watch;

use crate::{
    assets::NetworkReadiness,
    network::connectivity::{
        first_hand_indexer_heights::{FirstHandIndexerHeights, ReportedIndexerHeight},
        health::{CheckComputationSupport, EstablishedConnections},
    },
    providers::participant_selection::ComputationDuration,
};

/// Derives the [`NetworkReadiness`] for computations of `duration` from the connections and
/// first-hand indexer heights the monitor publishes, and publishes it whenever it changes.
struct NetworkReadinessPublisher<N, S> {
    me: N,
    duration: ComputationDuration,
    max_indexer_height_lag: BlockCount,
    refresh_interval: Duration,
    clock: Clock,
    connections: watch::Receiver<Arc<EstablishedConnections<N, S>>>,
    heights: watch::Receiver<FirstHandIndexerHeights<N>>,
    readiness: watch::Sender<NetworkReadiness<N>>,
}

impl<N, S> NetworkReadinessPublisher<N, S>
where
    N: Ord + Hash + Clone,
    S: CheckComputationSupport,
{
    fn new(
        me: N,
        duration: ComputationDuration,
        max_indexer_height_lag: BlockCount,
        refresh_interval: Duration,
        clock: Clock,
        connections: watch::Receiver<Arc<EstablishedConnections<N, S>>>,
        heights: watch::Receiver<FirstHandIndexerHeights<N>>,
    ) -> (Self, watch::Receiver<NetworkReadiness<N>>) {
        let initial = derive_network_readiness(
            &me,
            &heights.borrow(),
            &connections.borrow(),
            duration,
            max_indexer_height_lag,
            clock.now(),
        );
        let (readiness, readiness_receiver) = watch::channel(initial);
        let publisher = Self {
            me,
            duration,
            max_indexer_height_lag,
            refresh_interval,
            clock,
            connections,
            heights,
            readiness,
        };
        (publisher, readiness_receiver)
    }

    /// Derives again when a connection changes, and every `refresh_interval` to pick up the
    /// indexer heights and what the passing of time changes. The heights are not a wake-up
    /// source: they change with every report. Runs until the monitor is gone or nothing reads the
    /// result any more.
    async fn run(mut self) {
        loop {
            tokio::select! {
                changed = self.connections.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = self.readiness.closed() => return,
                _ = self.clock.sleep(self.refresh_interval) => {}
            }
            let readiness = derive_network_readiness(
                &self.me,
                &self.heights.borrow(),
                &self.connections.borrow(),
                self.duration,
                self.max_indexer_height_lag,
                self.clock.now(),
            );
            self.readiness.send_if_modified(|published| {
                if *published == readiness {
                    return false;
                }
                *published = readiness;
                true
            });
        }
    }
}

fn derive_network_readiness<N, S>(
    me: &N,
    heights: &FirstHandIndexerHeights<N>,
    connections: &EstablishedConnections<N, S>,
    duration: ComputationDuration,
    max_indexer_height_lag: BlockCount,
    now: Instant,
) -> NetworkReadiness<N>
where
    N: Ord + Hash + Clone,
    S: CheckComputationSupport,
{
    NetworkReadiness::new(
        alive_participants(me, heights, max_indexer_height_lag),
        connections.connections_not_supporting(duration, now),
    )
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
            mine.blocks_since(peer) > max_lag
        }
    }
}
