use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::Tick;

/// Advances the loop under test by a counted number of rounds rather than by elapsed time.
#[derive(Clone)]
pub struct MockTicker {
    scheduled: Arc<Semaphore>,
}

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
