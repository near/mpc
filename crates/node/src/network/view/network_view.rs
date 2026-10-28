use crate::network::constants::RECENT_DELAY_SAMPLES;
use crate::primitives::{ParticipantId, PeerConnectedPeersInfo};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug)]
pub struct NetworkView {
    me: ParticipantId,
    participants: BTreeSet<ParticipantId>,
    first_hand: BTreeMap<ParticipantId, u64>,
    connections: BTreeMap<Connection, ConnectionHistory>,
}

impl NetworkView {
    pub fn new(me: ParticipantId, participants: &[ParticipantId]) -> Self {
        Self {
            me,
            participants: participants.iter().copied().collect(),
            first_hand: BTreeMap::new(),
            connections: BTreeMap::new(),
        }
    }

    /// Returns the `peer -> reporter` connections this message refreshed.
    pub fn update_with_info(
        &mut self,
        info: PeerConnectedPeersInfo,
    ) -> Vec<(Connection, ConnectionState)> {
        let reported_peer_heights = &info.info.peers;
        let reporter = info.from;
        if let Some(&own) = reported_peer_heights.get(&reporter)
            && own != 0
        {
            self.first_hand.insert(reporter, own);
        }
        let mut refreshed = Vec::new();
        for &peer in &self.participants {
            if peer == reporter {
                continue;
            }
            let report = match reported_peer_heights.get(&peer) {
                None | Some(&0) => ConnectionReport::Disconnected,
                Some(&heard) => {
                    let Some(&first_hand) = self.first_hand.get(&peer) else {
                        continue;
                    };
                    ConnectionReport::Delay(first_hand.saturating_sub(heard))
                }
            };
            let connection = Connection {
                from: peer,
                to: reporter,
            };
            refreshed.push(Self::record(&mut self.connections, connection, report));
        }
        refreshed
    }

    /// A participant's own indexer height: ours from the indexer, a legacy peer's from its
    /// `IndexerHeight` message.
    pub fn update_indexer_height(&mut self, participant: ParticipantId, height: u64) {
        if height != 0 {
            self.first_hand.insert(participant, height);
        }
    }

    /// Returns the `peer -> me` connections this set refreshed.
    pub fn update_connected_peers(
        &mut self,
        connected: &BTreeSet<ParticipantId>,
    ) -> Vec<(Connection, ConnectionState)> {
        let mut refreshed = Vec::new();
        for &peer in &self.participants {
            if peer == self.me {
                continue;
            }
            let report = if connected.contains(&peer) {
                ConnectionReport::Connected
            } else {
                ConnectionReport::Disconnected
            };
            let connection = Connection {
                from: peer,
                to: self.me,
            };
            refreshed.push(Self::record(&mut self.connections, connection, report));
        }
        refreshed
    }

    pub fn indexer_height(&self, participant: ParticipantId) -> Option<u64> {
        self.first_hand.get(&participant).copied()
    }

    pub fn participants(&self) -> impl Iterator<Item = ParticipantId> + '_ {
        self.participants.iter().copied()
    }

    fn record(
        connections: &mut BTreeMap<Connection, ConnectionHistory>,
        connection: Connection,
        report: ConnectionReport,
    ) -> (Connection, ConnectionState) {
        let history = connections
            .entry(connection)
            .and_modify(|history| history.record_latest(report))
            .or_insert_with(|| ConnectionHistory::new(report));
        (connection, history.state())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Connection {
    pub from: ParticipantId,
    pub to: ParticipantId,
}

impl Connection {
    pub fn inverse(&self) -> Connection {
        Connection {
            from: self.to,
            to: self.from,
        }
    }
}

#[derive(Debug)]
struct ConnectionHistory {
    reports: VecDeque<ConnectionReport>,
    state: ConnectionState,
}

impl ConnectionHistory {
    fn new(report: ConnectionReport) -> Self {
        let mut reports = VecDeque::with_capacity(RECENT_DELAY_SAMPLES);
        reports.push_back(report);
        let state = Self::state_of(&reports);
        Self { reports, state }
    }

    fn record_latest(&mut self, report: ConnectionReport) {
        if self.reports.len() == RECENT_DELAY_SAMPLES {
            self.reports.pop_front();
        }
        self.reports.push_back(report);
        self.state = Self::state_of(&self.reports);
    }

    fn state_of(reports: &VecDeque<ConnectionReport>) -> ConnectionState {
        match reports.back() {
            None | Some(ConnectionReport::Disconnected) => ConnectionState::Disconnected,
            Some(ConnectionReport::Connected) => ConnectionState::Connected,
            Some(ConnectionReport::Delay(_)) => {
                let (mut summed_delays, mut n_reports) = (0u128, 0u128);
                for report in reports.iter().rev() {
                    let ConnectionReport::Delay(delay) = report else {
                        break;
                    };
                    summed_delays = summed_delays.saturating_add(u128::from(*delay));
                    n_reports = n_reports.saturating_add(1);
                }
                let avg = summed_delays.checked_div(n_reports).unwrap_or(0);
                ConnectionState::Delay(u64::try_from(avg).unwrap_or(u64::MAX))
            }
        }
    }

    fn state(&self) -> ConnectionState {
        self.state
    }
}

#[derive(Debug, Clone, Copy)]
enum ConnectionReport {
    Connected,
    Delay(u64),
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    // TODO(#398): remove once the protocol floor is Oct2026; an empty history is then Disconnected.
    Unknown,
    /// The transport reports a bidirectional connection; no delay is measured in this direction.
    Connected,
    Delay(u64),
    Disconnected,
}

impl ConnectionState {
    pub fn worse(self, other: Self) -> Self {
        match (self, other) {
            (Self::Disconnected, _) | (_, Self::Disconnected) => Self::Disconnected,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Connected, other) | (other, Self::Connected) => other,
            (Self::Delay(a), Self::Delay(b)) => Self::Delay(a.max(b)),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{Connection, ConnectionHistory, ConnectionReport, ConnectionState, NetworkView};
    use crate::network::constants::RECENT_DELAY_SAMPLES;
    use crate::primitives::{ConnectedPeersInfo, ParticipantId, PeerConnectedPeersInfo};
    use rstest::rstest;
    use std::collections::{BTreeMap, BTreeSet};

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const A: ParticipantId = ParticipantId::from_raw(1);
    const B: ParticipantId = ParticipantId::from_raw(2);
    const C: ParticipantId = ParticipantId::from_raw(3);
    const PARTICIPANTS: [ParticipantId; 4] = [ME, A, B, C];
    const H: u64 = 1_000;

    type Peers<'a> = &'a [(ParticipantId, u64)];

    const fn connection(from: ParticipantId, to: ParticipantId) -> Connection {
        Connection { from, to }
    }

    fn info(from: ParticipantId, peers: Peers) -> PeerConnectedPeersInfo {
        PeerConnectedPeersInfo {
            from,
            info: ConnectedPeersInfo {
                peers: peers.iter().copied().collect(),
            },
        }
    }

    fn connection_states_after(
        updates: &[(ParticipantId, Peers)],
    ) -> BTreeMap<Connection, ConnectionState> {
        let mut view = NetworkView::new(ME, &PARTICIPANTS);
        let mut states = BTreeMap::new();
        for (from, peers) in updates {
            states.extend(view.update_with_info(info(*from, peers)));
        }
        states
    }

    fn recent_delays_after(samples: &[Option<u64>]) -> ConnectionHistory {
        let mut reports = samples
            .iter()
            .map(|sample| sample.map_or(ConnectionReport::Disconnected, ConnectionReport::Delay));
        let mut delays = ConnectionHistory::new(reports.next().expect("at least one sample"));
        for report in reports {
            delays.record_latest(report);
        }
        delays
    }

    #[test]
    fn recent_delays__should_be_disconnected_when_the_latest_sample_is_none() {
        // Given
        let delays = recent_delays_after(&[Some(3), None]);

        // When
        let delay = delays.state();

        // Then
        assert_eq!(delay, ConnectionState::Disconnected);
    }

    #[test]
    fn recent_delays__should_evict_the_oldest_sample_past_the_cap() {
        // Given
        let mut samples = vec![Some(1_000)];
        samples.extend(std::iter::repeat_n(Some(0), RECENT_DELAY_SAMPLES));
        let delays = recent_delays_after(&samples);

        // When
        let delay = delays.state();

        // Then
        assert_eq!(delay, ConnectionState::Delay(0));
    }

    #[test]
    fn network_view__should_disconnect_a_pair_the_reporter_omits() {
        // Given
        let updates = [
            (A, &[(A, H), (ME, H)][..]),
            (B, &[(B, H), (A, H), (ME, H)][..]),
        ];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(B, A)], ConnectionState::Disconnected);
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(0));
    }

    #[test]
    fn network_view__should_disconnect_a_pair_the_reporter_lists_without_a_height() {
        // Given
        let updates = [(A, &[(A, H), (B, H)][..]), (B, &[(B, H), (A, 0)][..])];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(A, B)], ConnectionState::Disconnected);
    }

    #[test]
    fn network_view__should_measure_delay_as_first_hand_minus_heard() {
        // Given
        let updates = [
            (B, &[(B, H), (A, H)][..]),
            (A, &[(A, H), (B, H)][..]),
            (B, &[(B, H), (A, H - 4)][..]),
        ];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(4));
    }

    #[test]
    fn network_view__should_average_delay_over_successive_rows() {
        // Given
        let updates = [
            (B, &[(B, H), (A, H)][..]),
            (A, &[(A, H), (B, H)][..]),
            (B, &[(B, H), (A, H - 4)][..]),
            (B, &[(B, H), (A, H - 6)][..]),
        ];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(5));
    }

    #[test]
    fn network_view__should_restart_the_average_after_a_reconnect() {
        // Given
        let updates = [
            (B, &[(B, H), (A, H)][..]),
            (A, &[(A, H), (B, H)][..]),
            (B, &[(B, H), (A, H - 8)][..]),
            (B, &[(B, H)][..]),
            (B, &[(B, H), (A, H - 2)][..]),
        ];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(2));
    }

    #[rstest]
    #[case::no_info_from_a_yet(&[(B, &[(B, H), (A, H - 4)][..])])]
    #[case::own_entry_of_a_is_zero(&[(A, &[(A, 0), (B, H)][..]), (B, &[(B, H), (A, H - 4)][..])])]
    fn network_view__should_skip_samples_while_a_height_is_unknown(
        #[case] updates: &[(ParticipantId, Peers)],
    ) {
        // Given
        let states = connection_states_after(updates);

        // When
        let state = states.get(&connection(A, B));

        // Then
        assert_eq!(state, None);
    }

    #[test]
    fn network_view__should_saturate_when_hearsay_is_fresher_than_first_hand() {
        // Given
        let updates = [
            (B, &[(B, H), (A, H)][..]),
            (A, &[(A, H - 10), (B, H)][..]),
            (B, &[(B, H), (A, H)][..]),
        ];

        // When
        let states = connection_states_after(&updates);

        // Then
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(0));
    }

    #[test]
    fn network_view__should_measure_our_outbound_delay_against_our_indexer_height() {
        // Given
        let mut view = NetworkView::new(ME, &PARTICIPANTS);
        view.update_indexer_height(ME, H);

        // When
        let refreshed = view.update_with_info(info(A, &[(A, H), (ME, H - 3)]));

        // Then
        let states: BTreeMap<_, _> = refreshed.into_iter().collect();
        assert_eq!(states[&connection(ME, A)], ConnectionState::Delay(3));
    }

    #[test]
    fn network_view__should_record_our_connected_peers_as_connected_and_the_rest_as_disconnected() {
        // Given
        let mut view = NetworkView::new(ME, &PARTICIPANTS);

        // When
        let refreshed = view.update_connected_peers(&BTreeSet::from([A]));

        // Then
        let states: BTreeMap<_, _> = refreshed.into_iter().collect();
        assert_eq!(states[&connection(A, ME)], ConnectionState::Connected);
        assert_eq!(states[&connection(B, ME)], ConnectionState::Disconnected);
        assert_eq!(states[&connection(C, ME)], ConnectionState::Disconnected);
        assert_eq!(states.len(), 3);
    }

    #[test]
    fn network_view__should_reconnect_a_peer_that_reappears_in_our_connected_peers() {
        // Given
        let mut view = NetworkView::new(ME, &PARTICIPANTS);
        view.update_connected_peers(&BTreeSet::new());

        // When
        let refreshed = view.update_connected_peers(&BTreeSet::from([A]));

        // Then
        let states: BTreeMap<_, _> = refreshed.into_iter().collect();
        assert_eq!(states[&connection(A, ME)], ConnectionState::Connected);
    }

    #[rstest]
    #[case::unknown(ConnectionState::Unknown)]
    #[case::delay(ConnectionState::Delay(3))]
    #[case::disconnected(ConnectionState::Disconnected)]
    fn connection_state__should_treat_connected_as_the_identity_under_worse(
        #[case] other: ConnectionState,
    ) {
        // Given
        let connected = ConnectionState::Connected;

        // When
        let worse = connected.worse(other);

        // Then
        assert_eq!(worse, other);
        assert_eq!(other.worse(connected), other);
    }
}
