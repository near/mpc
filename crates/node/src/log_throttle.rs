use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Suppress,
    Emit { observed: u64 },
}

pub struct LogThrottle {
    last_emit: Option<Instant>,
    observed: u64,
    interval: Duration,
}

impl LogThrottle {
    pub fn new(interval: Duration) -> Self {
        Self {
            last_emit: None,
            observed: 0,
            interval,
        }
    }

    pub fn check(&mut self, now: Instant) -> Decision {
        // Calculated as inclusive of current call
        self.observed = self.observed.saturating_add(1);
        if let Some(last) = self.last_emit
            && now.duration_since(last) < self.interval
        {
            return Decision::Suppress;
        }
        self.last_emit = Some(now);
        Decision::Emit {
            observed: self.observed,
        }
    }

    pub fn reset(&mut self) {
        self.last_emit = None;
        self.observed = 0;
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{Decision, LogThrottle};
    use std::time::{Duration, Instant};

    #[test]
    fn log_throttle__should_emit_on_first_check() {
        // Given
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(50));
        // When / Then
        assert_eq!(throttle.check(now), Decision::Emit { observed: 1 });
    }

    #[test]
    fn log_throttle__should_suppress_within_interval() {
        // Given
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(200));
        // When / Then
        assert_eq!(throttle.check(now), Decision::Emit { observed: 1 });
        assert_eq!(
            throttle.check(now + Duration::from_millis(50)),
            Decision::Suppress
        );
        assert_eq!(
            throttle.check(now + Duration::from_millis(100)),
            Decision::Suppress
        );
        assert_eq!(
            throttle.check(now + Duration::from_millis(150)),
            Decision::Suppress
        );
    }

    #[test]
    fn log_throttle__should_emit_suppression_count_after_interval() {
        // Given
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(30));
        // When
        assert_eq!(throttle.check(now), Decision::Emit { observed: 1 });
        assert_eq!(
            throttle.check(now + Duration::from_millis(5)),
            Decision::Suppress
        );
        assert_eq!(
            throttle.check(now + Duration::from_millis(10)),
            Decision::Suppress
        );
        assert_eq!(
            throttle.check(now + Duration::from_millis(50)),
            Decision::Emit { observed: 4 }
        );
        assert_eq!(
            throttle.check(now + Duration::from_millis(60)),
            Decision::Suppress
        );
        // Then
        assert_eq!(
            throttle.check(now + Duration::from_millis(90)),
            Decision::Emit { observed: 6 }
        );
    }

    #[test]
    fn log_throttle__should_emit_fresh_after_reset() {
        // Given
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_secs(2));
        // When
        assert_eq!(throttle.check(now), Decision::Emit { observed: 1 });
        assert_eq!(
            throttle.check(now + Duration::from_millis(100)),
            Decision::Suppress
        );
        // Then
        throttle.reset();
        assert_eq!(
            throttle.check(now + Duration::from_millis(200)),
            Decision::Emit { observed: 1 }
        );
    }
}
