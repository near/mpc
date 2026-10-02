//! Waiting for the next round of a periodic task.

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use tokio::sync::Semaphore;

/// Allows repeatedly awaiting for something, like a [`tokio::time::Interval`].
pub trait Tick {
    async fn tick(&mut self);
}

impl Tick for tokio::time::Interval {
    async fn tick(&mut self) {
        self.tick().await;
    }
}

/// Advances the loop under test by a counted number of rounds rather than by elapsed time.
#[cfg(test)]
#[derive(Clone)]
pub struct MockTicker {
    scheduled: Arc<Semaphore>,
}

#[cfg(test)]
impl MockTicker {
    pub fn new(count: usize) -> Self {
        Self {
            scheduled: Arc::new(Semaphore::new(count)),
        }
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
    async fn tick(&mut self) {
        let round = self
            .scheduled
            .acquire()
            .await
            .expect("the Semaphore is never closed");
        // Spend the round.
        round.forget();
    }
}
