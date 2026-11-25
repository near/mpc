//! Waiting for the next round of a periodic task.

#[cfg(feature = "test-utils")]
pub mod testing;

/// Allows repeatedly awaiting for something, like a [`tokio::time::Interval`].
pub trait Tick {
    fn tick(&mut self) -> impl Future<Output = ()> + Send;
}

impl Tick for tokio::time::Interval {
    async fn tick(&mut self) {
        self.tick().await;
    }
}
