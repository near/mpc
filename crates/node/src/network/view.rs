use crate::primitives::ParticipantId;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Which pairs of alive participants can reach each other, as seen from this node.
///
/// Edges incident to this node come from its own connection state. Any other edge is usable
/// only if both ends report it in a fresh
/// [`ConnectedPeersMessage`](crate::primitives::ConnectedPeersMessage) row. A peer without a
/// fresh row is unknown and never vetoes an edge, so peers that do not report (older node
/// versions, a stale row) keep today's behaviour: every alive pair counts as connected. A lying
/// reporter can therefore only remove edges incident to itself.
///
/// Equality covers the id sets only, so two views built from the same rows compare equal
/// regardless of when the rows arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkView {
    me: ParticipantId,
    alive: BTreeSet<ParticipantId>,
    reported: BTreeMap<ParticipantId, BTreeSet<ParticipantId>>,
}

impl NetworkView {
    /// `alive` is this node's own alive set, including itself. Rows from non-alive reporters or
    /// from this node are dropped, and every row is restricted to `alive`.
    pub fn new(
        me: ParticipantId,
        alive: &[ParticipantId],
        fresh_rows: HashMap<ParticipantId, BTreeSet<ParticipantId>>,
    ) -> Self {
        let alive: BTreeSet<ParticipantId> = alive.iter().copied().collect();
        let reported = fresh_rows
            .into_iter()
            .filter(|(reporter, _)| *reporter != me && alive.contains(reporter))
            .map(|(reporter, row)| (reporter, row.intersection(&alive).copied().collect()))
            .collect();
        Self {
            me,
            alive,
            reported,
        }
    }

    pub fn is_connected(&self, a: ParticipantId, b: ParticipantId) -> bool {
        if !(self.alive.contains(&a) && self.alive.contains(&b)) {
            return false;
        }
        if a == b || a == self.me || b == self.me {
            return true;
        }
        self.reports(a, b) && self.reports(b, a)
    }

    /// Alive pairs `(a, b)` with `a < b` that are not connected.
    pub fn broken_pairs(&self) -> BTreeSet<(ParticipantId, ParticipantId)> {
        self.alive
            .iter()
            .flat_map(|a| {
                self.alive
                    .range((std::ops::Bound::Excluded(*a), std::ops::Bound::Unbounded))
                    .map(move |b| (*a, *b))
            })
            .filter(|(a, b)| !self.is_connected(*a, *b))
            .collect()
    }

    /// Alive peers without a fresh row; their edges fall back to the local view.
    pub fn unknown_peers(&self) -> BTreeSet<ParticipantId> {
        self.alive
            .iter()
            .copied()
            .filter(|p| *p != self.me && !self.reported.contains_key(p))
            .collect()
    }

    fn reports(&self, from: ParticipantId, to: ParticipantId) -> bool {
        self.reported.get(&from).is_none_or(|row| row.contains(&to))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::NetworkView;
    use crate::primitives::ParticipantId;
    use rstest::rstest;
    use std::collections::{BTreeSet, HashMap};

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const A: ParticipantId = ParticipantId::from_raw(1);
    const B: ParticipantId = ParticipantId::from_raw(2);
    const C: ParticipantId = ParticipantId::from_raw(3);
    const STRANGER: ParticipantId = ParticipantId::from_raw(9);

    fn view(alive: &[ParticipantId], rows: &[(ParticipantId, &[ParticipantId])]) -> NetworkView {
        let rows: HashMap<ParticipantId, BTreeSet<ParticipantId>> = rows
            .iter()
            .map(|(reporter, peers)| (*reporter, peers.iter().copied().collect()))
            .collect();
        NetworkView::new(ME, alive, rows)
    }

    #[test]
    fn network_view__should_connect_own_edges_when_both_ends_alive() {
        // Given
        let view = view(&[ME, A, B], &[(A, &[B]), (B, &[A])]);

        // When
        let connected = view.is_connected(ME, A) && view.is_connected(A, ME);

        // Then
        assert!(connected);
    }

    #[rstest]
    #[case::both_report(&[(A, &[B][..]), (B, &[A][..])], true)]
    #[case::only_a_reports(&[(A, &[B][..]), (B, &[][..])], false)]
    #[case::neither_reports(&[(A, &[][..]), (B, &[][..])], false)]
    fn network_view__should_require_both_ends_to_report_an_edge(
        #[case] rows: &[(ParticipantId, &[ParticipantId])],
        #[case] expected: bool,
    ) {
        // Given
        let view = view(&[ME, A, B], rows);

        // When
        let connected = view.is_connected(A, B);

        // Then
        assert_eq!(connected, expected);
        assert_eq!(view.is_connected(B, A), expected);
    }

    #[rstest]
    #[case::a_unknown_b_reports(&[(B, &[A][..])], true)]
    #[case::both_unknown(&[], true)]
    #[case::a_unknown_b_omits(&[(B, &[][..])], false)]
    fn network_view__should_treat_a_peer_without_row_as_reporting_everything(
        #[case] rows: &[(ParticipantId, &[ParticipantId])],
        #[case] expected: bool,
    ) {
        // Given
        let view = view(&[ME, A, B], rows);

        // When
        let connected = view.is_connected(A, B);

        // Then
        assert_eq!(connected, expected);
    }

    #[test]
    fn network_view__should_not_connect_a_participant_that_is_not_alive() {
        // Given
        let view = view(&[ME, A], &[(A, &[B]), (B, &[A])]);

        // When
        let to_peer = view.is_connected(A, B);
        let to_me = view.is_connected(ME, B);
        let to_itself = view.is_connected(B, B);

        // Then
        assert!(!to_peer && !to_me && !to_itself);
    }

    #[test]
    fn network_view__should_drop_rows_from_non_alive_or_own_participants_and_ids_outside_alive() {
        // Given
        let rows: &[(ParticipantId, &[ParticipantId])] =
            &[(ME, &[A]), (STRANGER, &[A, B]), (A, &[B, STRANGER])];

        // When
        let view = view(&[ME, A, B], rows);

        // Then
        assert_eq!(view, self::view(&[ME, A, B], &[(A, &[B])]));
        assert_eq!(view.unknown_peers(), BTreeSet::from([B]));
        assert!(view.broken_pairs().is_empty());
    }

    #[test]
    fn network_view__should_list_each_broken_pair_once_with_smaller_id_first() {
        // Given
        let view = view(&[ME, A, B, C], &[(A, &[C]), (B, &[C]), (C, &[A, B])]);

        // When
        let broken = view.broken_pairs();

        // Then
        assert_eq!(broken, BTreeSet::from([(A, B)]));
    }
}
