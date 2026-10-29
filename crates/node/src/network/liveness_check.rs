use crate::network::rfc1982::Serial8;
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_MAX_OUTSTANDING_PINGS: usize = 32;

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
        Self::with_capacity(DEFAULT_MAX_OUTSTANDING_PINGS)
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

    pub fn prepare_next_nonce(&mut self) -> Serial8 {
        self.next_nonce.next()
    }

    pub fn start_echo(&mut self, nonce: Serial8, sent_at: Instant, timeout: Duration) -> bool {
        if self.outstanding.len() >= self.max_outstanding {
            return false;
        }
        if self.outstanding.iter().any(|p| p.nonce == nonce) {
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
            .position(|p| p.nonce == incoming_nonce)
        {
            let ping = self.outstanding.swap_remove(idx);
            Some(
                now.checked_duration_since(ping.sent_at)
                    .unwrap_or(Duration::ZERO),
            )
        } else {
            None
        }
    }

    pub fn check_timeouts(&mut self, now: Instant) -> bool {
        let initial_len = self.outstanding.len();
        self.outstanding.retain(|ping| now < ping.deadline);
        self.outstanding.len() < initial_len
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.outstanding.iter().map(|ping| ping.deadline).min()
    }

    pub fn is_awaiting_pong(&self) -> bool {
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
        assert!(tracker.is_awaiting_pong());
        let time_warp_2 = base_time + Duration::from_millis(3500);
        let rtt = tracker.receive_ack(nonce, time_warp_2);
        assert_eq!(rtt, Some(Duration::from_millis(3500)));
        assert!(!tracker.is_awaiting_pong());
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
        assert!(!tracker.is_awaiting_pong());
    }
}
