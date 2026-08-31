//! Waiting for the next round of a periodic task.

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// Allows repeatedly awaiting for something, like a [`tokio::time::Interval`]. The returned instant
/// is when the next round falls due, so it bounds the round just started.
pub trait Tick {
    async fn tick(&mut self) -> Instant;
}

impl Tick for tokio::time::Interval {
    async fn tick(&mut self) -> Instant {
        self.tick().await + self.period()
    }
}

/// Advances the loop under test by a counted number of rounds rather than by elapsed time.
#[cfg(test)]
#[derive(Clone)]
pub struct MockTicker {
    scheduled: Arc<Semaphore>,
    period: Duration,
}

#[cfg(test)]
impl MockTicker {
    pub fn new(count: usize) -> Self {
        Self {
            scheduled: Arc::new(Semaphore::new(count)),
            period: Duration::ZERO,
        }
    }

    /// Sets how long after each round the next one falls due.
    pub fn with_period(mut self, period: Duration) -> Self {
        self.period = period;
        self
    }

    /// Lets the loop run `count` more rounds, from its next poll onwards.
    pub fn schedule(&self, count: usize) {
        self.scheduled.add_permits(count);
    }

    /// Rounds scheduled but not yet taken by a loop.
    pub fn unspent(&self) -> usize {
        self.scheduled.available_permits()
    }
}

#[cfg(test)]
impl Tick for MockTicker {
    async fn tick(&mut self) -> Instant {
        let round = self
            .scheduled
            .acquire()
            .await
            .expect("the Semaphore is never closed");
        // Spend the round.
        round.forget();
        Instant::now() + self.period
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn tick__should_report_the_next_round_as_the_deadline() {
        // Given
        let period = Duration::from_secs(60);
        let mut interval = tokio::time::interval(period);
        let started_at = Instant::now();

        // When
        let deadline = Tick::tick(&mut interval).await;

        // Then
        assert_eq!(deadline, started_at + period);
    }
}
