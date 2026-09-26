use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Suppress,
    Emit { suppressed: u64 },
}

pub struct LogThrottle {
    last_emit: Option<Instant>,
    suppressed: u64,
    interval: Duration,
}

impl LogThrottle {
    pub fn new(interval: Duration) -> Self {
        Self {
            last_emit: None,
            suppressed: 0,
            interval,
        }
    }

    /// Determines decision. Returns `Decision::Emit` on the first call and again after `interval` expiry, otherwise `Desicion::Suppress`
    pub fn check(&mut self, now: Instant) -> Decision {
        if let Some(last) = self.last_emit
            && now.duration_since(last) < self.interval
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return Decision::Suppress;
        }
        let suppressed = self.suppressed;
        self.suppressed = 0;
        self.last_emit = Some(now);
        Decision::Emit { suppressed }
    }

    /// Clears state
    pub fn reset(&mut self) {
        self.last_emit = None;
        self.suppressed = 0;
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{Decision, LogThrottle};
    use std::time::{Duration, Instant};

    #[test]
    fn log_throttle__should_emit_on_first_check() {
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(50));
        assert_eq!(throttle.check(now), Decision::Emit { suppressed: 0 });
    }

    #[test]
    fn log_throttle__should_suppress_within_interval() {
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(200));
        assert_eq!(throttle.check(now), Decision::Emit { suppressed: 0 });
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
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_millis(30));
        assert_eq!(throttle.check(now), Decision::Emit { suppressed: 0 });
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
            Decision::Emit { suppressed: 2 }
        );

        assert_eq!(
            throttle.check(now + Duration::from_millis(60)),
            Decision::Suppress
        );

        assert_eq!(
            throttle.check(now + Duration::from_millis(90)),
            Decision::Emit { suppressed: 1 }
        );
    }

    #[test]
    fn log_throttle__should_emit_fresh_after_reset() {
        let now = Instant::now();
        let mut throttle = LogThrottle::new(Duration::from_secs(2));
        assert_eq!(throttle.check(now), Decision::Emit { suppressed: 0 });
        assert_eq!(
            throttle.check(now + Duration::from_millis(100)),
            Decision::Suppress
        );
        throttle.reset();
        assert_eq!(
            throttle.check(now + Duration::from_millis(200)),
            Decision::Emit { suppressed: 0 }
        );
    }
}
