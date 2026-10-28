use crate::network::constants::RECENT_DELAY_SAMPLES;
use crate::primitives::ParticipantId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug)]
pub struct NetworkView {
    participants: BTreeSet<ParticipantId>,
    first_hand: BTreeMap<ParticipantId, u64>,
    connections: BTreeMap<Connection, ConnectionHistory>,
}

impl NetworkView {
    pub fn new(participants: &[ParticipantId]) -> Self {
        Self {
            participants: participants.iter().copied().collect(),
            first_hand: BTreeMap::new(),
            connections: BTreeMap::new(),
        }
    }

    // todo: returns all connections and participants that have changed due to the update
    pub fn update_with_reported_heights(
        &mut self,
        reporter: ParticipantId,
        reported_peer_heights: &BTreeMap<ParticipantId, u64>,
    ) -> BTreeSet<Link> {
        if let Some(&own) = reported_peer_heights.get(&reporter)
            && own != 0
        {
            self.first_hand.insert(reporter, own);
        }
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
            // todo: compare against existing and add to set of reported changes
            self.connections
                .entry(Connection {
                    from: peer,
                    to: reporter,
                })
                .and_modify(|history| history.record_latest(report))
                .or_insert_with(|| ConnectionHistory::new(report));
        }
    }

    pub fn max_delay(&self, a: ParticipantId, b: ParticipantId) -> ConnectionState {
        let connection = Connection { from: a, to: b };
        self.state(&connection)
            .worse(self.state(&connection.inverse()))
    }

    fn state(&self, connection: &Connection) -> ConnectionState {
        self.connections
            .get(connection)
            .map_or(ConnectionState::Unknown, ConnectionHistory::state)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Connection {
    from: ParticipantId,
    to: ParticipantId,
}

impl Connection {
    fn inverse(&self) -> Connection {
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
    Delay(u64),
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    // TODO(#398): remove once the protocol floor is Oct2026; an empty history is then Disconnected.
    Unknown,
    Delay(u64),
    Disconnected,
}

impl ConnectionState {
    fn worse(self, other: Self) -> Self {
        match (self, other) {
            (Self::Disconnected, _) | (_, Self::Disconnected) => Self::Disconnected,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Delay(a), Self::Delay(b)) => Self::Delay(a.max(b)),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ConnectionHistory, ConnectionReport, ConnectionState, NetworkView};
    use crate::network::constants::RECENT_DELAY_SAMPLES;
    use crate::primitives::ParticipantId;
    use rstest::rstest;
    use std::collections::BTreeMap;

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const A: ParticipantId = ParticipantId::from_raw(1);
    const B: ParticipantId = ParticipantId::from_raw(2);
    const C: ParticipantId = ParticipantId::from_raw(3);
    const PARTICIPANTS: [ParticipantId; 4] = [ME, A, B, C];
    const H: u64 = 1_000;

    type Row<'a> = &'a [(ParticipantId, u64)];

    fn view_after(updates: &[(ParticipantId, Row)]) -> NetworkView {
        let mut view = NetworkView::new(&PARTICIPANTS);
        for (from, row) in updates {
            let row: BTreeMap<ParticipantId, u64> = row.iter().copied().collect();
            view.update_with_reported_heights(*from, &row);
        }
        view
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
    fn network_view__should_report_unknown_for_an_unsampled_pair() {
        // Given
        let view = view_after(&[]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Unknown);
    }

    #[test]
    fn network_view__should_disconnect_a_pair_the_reporter_omits() {
        // Given
        let view = view_after(&[(A, &[(A, H), (ME, H)]), (B, &[(B, H), (A, H), (ME, H)])]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Disconnected);
        assert_eq!(view.max_delay(B, A), ConnectionState::Disconnected);
    }

    #[test]
    fn network_view__should_disconnect_a_pair_the_reporter_lists_without_a_height() {
        // Given
        let view = view_after(&[(A, &[(A, H), (B, H)]), (B, &[(B, H), (A, 0)])]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Disconnected);
    }

    #[test]
    fn network_view__should_measure_delay_as_first_hand_minus_heard() {
        // Given
        let view = view_after(&[
            (B, &[(B, H), (A, H)]),
            (A, &[(A, H), (B, H)]),
            (B, &[(B, H), (A, H - 4)]),
        ]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Delay(4));
    }

    #[test]
    fn network_view__should_average_delay_over_successive_rows() {
        // Given
        let view = view_after(&[
            (B, &[(B, H), (A, H)]),
            (A, &[(A, H), (B, H)]),
            (B, &[(B, H), (A, H - 4)]),
            (B, &[(B, H), (A, H - 6)]),
        ]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Delay(5));
    }

    #[test]
    fn network_view__should_take_the_worse_direction() {
        // Given
        let view = view_after(&[
            (A, &[(A, H), (B, H)]),
            (B, &[(B, H), (A, H - 2)]),
            (A, &[(A, H), (B, H - 8)]),
        ]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Delay(8));
    }

    #[test]
    fn network_view__should_restart_the_average_after_a_reconnect() {
        // Given
        let view = view_after(&[
            (B, &[(B, H), (A, H)]),
            (A, &[(A, H), (B, H)]),
            (B, &[(B, H), (A, H - 8)]),
            (B, &[(B, H)]),
            (B, &[(B, H), (A, H - 2)]),
        ]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Delay(2));
    }

    #[rstest]
    #[case::no_row_from_a_yet(&[(B, &[(B, H), (A, H - 4)][..])])]
    #[case::own_entry_of_a_is_zero(&[(A, &[(A, 0), (B, H)][..]), (B, &[(B, H), (A, H - 4)][..])])]
    fn network_view__should_skip_samples_while_a_height_is_unknown(
        #[case] updates: &[(ParticipantId, Row)],
    ) {
        // Given
        let view = view_after(updates);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Unknown);
    }

    #[test]
    fn network_view__should_saturate_when_hearsay_is_fresher_than_first_hand() {
        // Given
        let view = view_after(&[
            (B, &[(B, H), (A, H)]),
            (A, &[(A, H - 10), (B, H)]),
            (B, &[(B, H), (A, H)]),
        ]);

        // When
        let delay = view.max_delay(A, B);

        // Then
        assert_eq!(delay, ConnectionState::Delay(0));
    }
}
