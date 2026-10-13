use crate::primitives::ParticipantId;
use crate::protocol_version::NetworkProtocolVersion;
use near_time::{Clock, Instant};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

/// Handshake protocol version that introduced
/// [`Packet::ConnectedPeers`](crate::network::wire_format::Packet::ConnectedPeers).
pub const CONNECTED_PEERS_MIN_PROTOCOL_VERSION: NetworkProtocolVersion =
    NetworkProtocolVersion::Oct2026;

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);

/// A row older than this is treated as absent, so a peer that stopped reporting falls back to
/// the local view instead of pinning its last claim.
pub const CONNECTED_PEERS_ROW_TTL: Duration = Duration::from_secs(5);

/// The latest connection row each peer reported, stamped with the local time of receipt.
pub struct ConnectedPeersTracker {
    clock: Clock,
    participants: HashSet<ParticipantId>,
    rows: Mutex<HashMap<ParticipantId, ReportedRow>>,
}

struct ReportedRow {
    peers: BTreeSet<ParticipantId>,
    received_at: Instant,
}

impl ConnectedPeersTracker {
    pub fn new(clock: Clock, participants: &[ParticipantId]) -> Self {
        Self {
            clock,
            participants: participants.iter().copied().collect(),
            rows: Mutex::new(HashMap::new()),
        }
    }

    /// Fails for a reporter outside the participant set. Ids outside the set, and the reporter
    /// itself, are dropped from the row.
    pub fn record(&self, from: ParticipantId, peers: &[ParticipantId]) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.participants.contains(&from),
            "participant {from} is not in our participant set"
        );
        let peers = peers
            .iter()
            .copied()
            .filter(|peer| *peer != from && self.participants.contains(peer))
            .collect();
        self.rows.lock().unwrap().insert(
            from,
            ReportedRow {
                peers,
                received_at: self.clock.now(),
            },
        );
        Ok(())
    }

    /// Rows received within [`CONNECTED_PEERS_ROW_TTL`].
    pub fn fresh_rows(&self) -> HashMap<ParticipantId, BTreeSet<ParticipantId>> {
        let now = self.clock.now();
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, row)| now.duration_since(row.received_at) <= CONNECTED_PEERS_ROW_TTL)
            .map(|(reporter, row)| (*reporter, row.peers.clone()))
            .collect()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{CONNECTED_PEERS_ROW_TTL, ConnectedPeersTracker};
    use crate::network::view::NetworkView;
    use crate::primitives::ParticipantId;
    use near_time::FakeClock;
    use std::collections::{BTreeSet, HashMap};

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const A: ParticipantId = ParticipantId::from_raw(1);
    const B: ParticipantId = ParticipantId::from_raw(2);
    const C: ParticipantId = ParticipantId::from_raw(3);
    const STRANGER: ParticipantId = ParticipantId::from_raw(9);
    const PARTICIPANTS: [ParticipantId; 4] = [ME, A, B, C];

    fn ttl() -> near_time::Duration {
        near_time::Duration::try_from(CONNECTED_PEERS_ROW_TTL).unwrap()
    }

    #[test]
    fn connected_peers_tracker__should_return_row_received_within_ttl() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);
        tracker.record(A, &[B, C]).unwrap();

        // When
        clock.advance(ttl());
        let rows = tracker.fresh_rows();

        // Then
        assert_eq!(rows, HashMap::from([(A, BTreeSet::from([B, C]))]));
    }

    #[test]
    fn connected_peers_tracker__should_omit_row_older_than_ttl() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);
        tracker.record(A, &[B, C]).unwrap();

        // When
        clock.advance(ttl() + near_time::Duration::seconds(1));
        let rows = tracker.fresh_rows();

        // Then
        assert!(rows.is_empty());
    }

    #[test]
    fn connected_peers_tracker__should_reject_row_from_unknown_reporter() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);

        // When
        let result = tracker.record(STRANGER, &[A]);

        // Then
        assert!(result.is_err());
        assert!(tracker.fresh_rows().is_empty());
    }

    #[test]
    fn connected_peers_tracker__should_drop_unknown_ids_and_reporter_from_row() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);

        // When
        tracker.record(A, &[A, B, STRANGER]).unwrap();

        // Then
        assert_eq!(
            tracker.fresh_rows(),
            HashMap::from([(A, BTreeSet::from([B]))])
        );
    }

    #[test]
    fn connected_peers_tracker__should_replace_previous_row_of_same_reporter() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);
        tracker.record(A, &[B]).unwrap();
        clock.advance(near_time::Duration::seconds(1));

        // When
        tracker.record(A, &[C]).unwrap();
        clock.advance(ttl());

        // Then
        assert_eq!(
            tracker.fresh_rows(),
            HashMap::from([(A, BTreeSet::from([C]))])
        );
    }

    #[test]
    fn network_view__should_compare_equal_regardless_of_report_age() {
        // Given
        let clock = FakeClock::default();
        let tracker = ConnectedPeersTracker::new(clock.clock(), &PARTICIPANTS);
        tracker.record(A, &[B]).unwrap();
        let earlier = NetworkView::new(ME, &PARTICIPANTS, tracker.fresh_rows());

        // When
        clock.advance(near_time::Duration::seconds(1));
        let later = NetworkView::new(ME, &PARTICIPANTS, tracker.fresh_rows());

        // Then
        assert_eq!(earlier, later);
    }
}
