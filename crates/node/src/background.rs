use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Tracks number of in-flight generations so we don't generate too many at the same time.
pub struct InFlightGenerationTracker {
    generations_in_flight: Arc<AtomicUsize>,
}

impl InFlightGenerationTracker {
    pub fn new() -> Self {
        Self {
            generations_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn in_flight(&self, count: usize) -> InFlightGenerations {
        InFlightGenerations::new(self.generations_in_flight.clone(), count)
    }

    pub fn num_in_flight(&self) -> usize {
        self.generations_in_flight
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn num_in_flight_atomic(&self) -> Arc<AtomicUsize> {
        self.generations_in_flight.clone()
    }
}

/// Drop guard to increment and decrement number of generations in flight.
pub struct InFlightGenerations {
    generations_in_flight: Arc<AtomicUsize>,
    count: usize,
}

impl InFlightGenerations {
    pub fn new(generations_in_flight: Arc<AtomicUsize>, count: usize) -> Self {
        generations_in_flight.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        Self {
            generations_in_flight,
            count,
        }
    }
}

impl Drop for InFlightGenerations {
    fn drop(&mut self) {
        self.generations_in_flight
            .fetch_sub(self.count, std::sync::atomic::Ordering::Relaxed);
    }
}
