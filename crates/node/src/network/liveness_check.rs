use crate::network::rfc1982::Serial8;
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_MAX_OUTSTANDING_ECHOES: usize = 32;

#[derive(Debug, Clone)]
pub struct EchoTracker {
    next_nonce: Serial8,
    outstanding: Vec<OutstandingEcho>,
    max_outstanding: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct OutstandingEcho {
    nonce: Serial8,
    sent_at: Instant,
    deadline: Instant,
}

impl Default for EchoTracker {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_OUTSTANDING_ECHOES)
    }
}

impl EchoTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_outstanding: usize) -> Self {
        Self {
            next_nonce: Serial8::default(),
            outstanding: Vec::with_capacity(max_outstanding),
            max_outstanding,
        }
    }

    pub fn with_next_nonce(mut self, next_nonce: Serial8) -> Self {
        self.next_nonce = next_nonce;
        self
    }

    pub fn next_nonce(&self) -> Serial8 {
        self.next_nonce
    }

    pub fn prepare_next_nonce(&mut self) -> Serial8 {
        self.next_nonce.next()
    }

    pub fn is_stale(&self, nonce: Serial8) -> bool {
        nonce.rfc1982_less_than(self.next_nonce)
    }

    pub fn start_echo(&mut self, nonce: Serial8, sent_at: Instant, timeout: Duration) -> bool {
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

    pub fn receive_ack(&mut self, incoming_nonce: Serial8, now: Instant) -> Option<Duration> {
        if let Some(idx) = self
            .outstanding
            .iter()
            .position(|echo| echo.nonce == incoming_nonce)
        {
            let echo = self.outstanding.swap_remove(idx);
            Some(
                now.checked_duration_since(echo.sent_at)
                    .unwrap_or(Duration::ZERO),
            )
        } else {
            None
        }
    }

    pub fn check_timeouts(&mut self, now: Instant) -> bool {
        let initial_len = self.outstanding.len();
        self.outstanding.retain(|echo| now < echo.deadline);
        self.outstanding.len() < initial_len
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.outstanding.iter().map(|echo| echo.deadline).min()
    }

    pub fn is_awaiting_ack(&self) -> bool {
        !self.outstanding.is_empty()
    }

    pub fn max_outstanding(&self) -> usize {
        self.max_outstanding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_time_warp() {
        // Given
        let mut tracker = EchoTracker::new();
        let base_time = Instant::now();
        let timeout = Duration::from_secs(5);
        let nonce = tracker.prepare_next_nonce();

        // When / Then
        assert!(tracker.start_echo(nonce, base_time, timeout));
        let time_warp_1 = base_time + Duration::from_millis(2500);
        assert!(!tracker.check_timeouts(time_warp_1));
        assert!(tracker.is_awaiting_ack());
        let time_warp_2 = base_time + Duration::from_millis(3500);
        let rtt = tracker.receive_ack(nonce, time_warp_2);
        assert_eq!(rtt, Some(Duration::from_millis(3500)));
        assert!(!tracker.is_awaiting_ack());
    }

    #[test]
    fn test_nonce_sequence_wraparound() {
        // Given
        let mut tracker = EchoTracker::new().with_next_nonce(Serial8::new(254));

        // When / Then
        assert_eq!(tracker.prepare_next_nonce(), Serial8::new(254));
        assert_eq!(tracker.prepare_next_nonce(), Serial8::new(255));
        assert_eq!(tracker.prepare_next_nonce(), Serial8::new(0));
        assert_eq!(tracker.next_nonce(), Serial8::new(1));
    }

    #[test]
    fn test_is_stale_only_for_nonces_before_the_next_one() {
        // Given
        let tracker = EchoTracker::new().with_next_nonce(Serial8::new(2));

        // When / Then
        assert!(tracker.is_stale(Serial8::new(1)));
        assert!(tracker.is_stale(Serial8::new(255)));
        assert!(!tracker.is_stale(Serial8::new(2)));
        assert!(!tracker.is_stale(Serial8::new(3)));
    }

    #[test]
    fn test_deterministic_expiry() {
        // Given
        let mut tracker = EchoTracker::new();
        let base_time = Instant::now();
        let timeout = Duration::from_secs(2);
        let nonce = tracker.prepare_next_nonce();
        // When / Then
        assert!(tracker.start_echo(nonce, base_time, timeout));
        let expired_warp = base_time + Duration::from_millis(2001);
        assert!(tracker.check_timeouts(expired_warp));
        assert!(!tracker.is_awaiting_ack());
    }
}
