use crate::primitives::ParticipantId;
use near_time::Clock;
use std::collections::HashMap;

pub struct RecentPeer {
    clock: Clock,
    grace: near_time::Duration,
    last_alive: HashMap<ParticipantId, near_time::Instant>,
}

impl RecentPeer {
    pub fn new(clock: Clock, participants: &[ParticipantId], grace: near_time::Duration) -> Self {
        let now = clock.now();
        Self {
            last_alive: participants.iter().map(|p| (*p, now)).collect(),
            clock,
            grace,
        }
    }

    pub fn observe(&mut self, alive: &[ParticipantId]) {
        let now = self.clock.now();
        for participant in alive {
            self.last_alive.insert(*participant, now);
        }
    }

    pub fn retained(&self) -> Vec<ParticipantId> {
        let now = self.clock.now();
        let mut retained: Vec<_> = self
            .last_alive
            .iter()
            .filter(|(_, last_alive)| now < **last_alive + self.grace)
            .map(|(participant, _)| *participant)
            .collect();
        retained.sort();
        retained
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::RecentPeer;
    use crate::primitives::ParticipantId;
    use near_time::{Duration, FakeClock};
    const GRACE: Duration = Duration::seconds(60);

    #[test]
    fn observe__should_retain_a_peer_again_when_it_comes_back() {
        // Given
        let clock = FakeClock::default();
        let mut recently_alive =
            RecentPeer::new(clock.clock(), &[0, 1].map(ParticipantId::from_raw), GRACE);
        clock.advance(Duration::seconds(120));
        recently_alive.observe(&[0].map(ParticipantId::from_raw));

        // When
        recently_alive.observe(&[0, 1].map(ParticipantId::from_raw));

        // Then
        assert_eq!(
            recently_alive.retained(),
            [0, 1].map(ParticipantId::from_raw)
        );
    }

    #[test]
    fn retained__should_expire_a_peer_at_the_grace_period() {
        // Given
        let clock = FakeClock::default();
        let mut recently_alive =
            RecentPeer::new(clock.clock(), &[0, 1].map(ParticipantId::from_raw), GRACE);

        // When
        clock.advance(GRACE - Duration::seconds(1));
        recently_alive.observe(&[0].map(ParticipantId::from_raw));

        // Then
        assert_eq!(
            recently_alive.retained(),
            &[0, 1].map(ParticipantId::from_raw)
        );
        clock.advance(Duration::seconds(1));
        assert_eq!(recently_alive.retained(), &[0].map(ParticipantId::from_raw));
    }
}
