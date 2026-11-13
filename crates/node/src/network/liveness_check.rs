use crate::network::rfc1982::Rfc1982SerialU8;
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_MAX_OUTSTANDING_ECHOES: usize = 32;

#[derive(Debug, Clone)]
pub struct EchoTracker {
    next_nonce: Rfc1982SerialU8,
    outstanding: Vec<OutstandingEcho>,
    max_outstanding: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct OutstandingEcho {
    nonce: Rfc1982SerialU8,
    sent_at: Instant,
    deadline: Instant,
}

impl Default for EchoTracker {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_OUTSTANDING_ECHOES)
    }
}

impl EchoTracker {
    pub fn with_capacity(max_outstanding: usize) -> Self {
        let max = max_outstanding.min(127);
        Self {
            next_nonce: Rfc1982SerialU8::default(),
            outstanding: Vec::with_capacity(max),
            max_outstanding: max,
        }
    }

    pub fn with_next_nonce(mut self, next_nonce: Rfc1982SerialU8) -> Self {
        self.next_nonce = next_nonce;
        self
    }

    pub fn next_nonce(&self) -> Rfc1982SerialU8 {
        self.next_nonce
    }

    pub fn prepare_next_nonce(&mut self) -> Rfc1982SerialU8 {
        self.next_nonce.post_increment()
    }

    pub fn is_stale(&self, nonce: Rfc1982SerialU8) -> bool {
        nonce.less_than(self.next_nonce)
    }

    pub fn start_echo(
        &mut self,
        nonce: Rfc1982SerialU8,
        sent_at: Instant,
        timeout: Duration,
    ) -> bool {
        if self.outstanding.len() >= self.max_outstanding {
            return false;
        }
        if self.outstanding.iter().any(|echo| echo.nonce == nonce) {
            return false;
        }
        let Some(deadline) = sent_at.checked_add(timeout) else {
            return false;
        };
        self.outstanding.push(OutstandingEcho {
            nonce,
            sent_at,
            deadline,
        });
        true
    }

    pub fn receive_ack(
        &mut self,
        incoming_nonce: Rfc1982SerialU8,
        now: Instant,
    ) -> Option<Duration> {
        let acked = *self
            .outstanding
            .iter()
            .find(|echo| echo.nonce == incoming_nonce)?;
        if now >= acked.deadline {
            return None;
        }
        self.outstanding
            .retain(|echo| echo.nonce.greater_than(acked.nonce));
        Some(now.saturating_duration_since(acked.sent_at))
    }

    pub fn check_timeouts(&mut self, now: Instant) -> bool {
        let initial_len = self.outstanding.len();
        self.outstanding.retain(|echo| now < echo.deadline);
        self.outstanding.len() < initial_len
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.outstanding.iter().map(|echo| echo.deadline).min()
    }

    pub fn max_outstanding(&self) -> usize {
        self.max_outstanding
    }
    
    #[cfg(test)]
    pub fn is_awaiting_ack(&self) -> bool {
        !self.outstanding.is_empty()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn echo_tracker__should_handle_time_warp_deterministically() {
        // Given
        let mut tracker = EchoTracker::default();
        let base_time = Instant::now();
        let timeout = Duration::from_secs(5);
        let nonce = tracker.prepare_next_nonce();

        // When / Then
        assert!(tracker.start_echo(nonce, base_time, timeout));
        let time_warp_1 = base_time.checked_add(Duration::from_millis(2500)).unwrap();
        assert!(!tracker.check_timeouts(time_warp_1));
        assert!(tracker.is_awaiting_ack());
        let time_warp_2 = base_time.checked_add(Duration::from_millis(3500)).unwrap();
        let rtt = tracker.receive_ack(nonce, time_warp_2);
        assert_eq!(rtt, Some(Duration::from_millis(3500)));
        assert!(!tracker.is_awaiting_ack());
    }

    #[test]
    fn echo_tracker__should_wraparound_for_nonce_sequence() {
        // Given
        let mut tracker = EchoTracker::default().with_next_nonce(Rfc1982SerialU8::new(254));

        // When / Then
        assert_eq!(tracker.prepare_next_nonce(), Rfc1982SerialU8::new(254));
        assert_eq!(tracker.prepare_next_nonce(), Rfc1982SerialU8::new(255));
        assert_eq!(tracker.prepare_next_nonce(), Rfc1982SerialU8::new(0));
        assert_eq!(tracker.next_nonce(), Rfc1982SerialU8::new(1));
    }

    #[test]
    fn echo_tracker__should_evaluate_nonces_before_next_as_stale() {
        // Given
        let tracker = EchoTracker::default().with_next_nonce(Rfc1982SerialU8::new(2));

        // When / Then
        assert!(tracker.is_stale(Rfc1982SerialU8::new(1)));
        assert!(tracker.is_stale(Rfc1982SerialU8::new(255)));
        assert!(!tracker.is_stale(Rfc1982SerialU8::new(2)));
        assert!(!tracker.is_stale(Rfc1982SerialU8::new(3)));
    }

    #[test]
    fn echo_tracker__should_have_deterministic_expiry() {
        // Given
        let mut tracker = EchoTracker::default();
        let base_time = Instant::now();
        let timeout = Duration::from_secs(2);
        let nonce = tracker.prepare_next_nonce();
        // When / Then
        assert!(tracker.start_echo(nonce, base_time, timeout));
        let expired_warp = base_time.checked_add(Duration::from_millis(2001)).unwrap();
        assert!(tracker.check_timeouts(expired_warp));
        assert!(!tracker.is_awaiting_ack());
    }

    #[test]
    fn echo_tracker__should_clear_earlier_unanswered_echoes_for_receive_ack() {
        // Given
        let mut tracker = EchoTracker::default();
        let t0 = Instant::now();
        let timeout = Duration::from_secs(10);
        let first = tracker.prepare_next_nonce();
        let second = tracker.prepare_next_nonce();
        assert!(tracker.start_echo(first, t0, timeout));
        assert!(tracker.start_echo(
            second,
            t0.checked_add(Duration::from_secs(5)).unwrap(),
            timeout
        ));

        // When
        let rtt = tracker.receive_ack(second, t0.checked_add(Duration::from_millis(5500)).unwrap());

        // Then
        assert_eq!(rtt, Some(Duration::from_millis(500)));
        assert!(!tracker.is_awaiting_ack());
        assert!(!tracker.check_timeouts(t0.checked_add(Duration::from_secs(11)).unwrap()));
    }
}
