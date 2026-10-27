use crate::metrics;
use crate::primitives::ParticipantId;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

/// Tracks the block height of the indexer of each participant.
pub struct IndexerHeightTracker {
    /// Keys are readonly; values are updated atomically.
    pub heights: HashMap<ParticipantId, AtomicU64>,
}

impl IndexerHeightTracker {
    pub fn new(participants: &[ParticipantId]) -> Self {
        let mut heights = HashMap::new();
        for participant in participants {
            heights.insert(*participant, AtomicU64::new(0));
        }
        Self { heights }
    }

    pub fn set_height(&self, participant: ParticipantId, height: u64) {
        let atomic = self.heights.get(&participant).unwrap();
        let current = atomic.load(std::sync::atomic::Ordering::Relaxed);
        if height > current {
            atomic.store(height, std::sync::atomic::Ordering::Relaxed);
        }

        if let Err(e) = metrics::PEERS_INDEXER_HEIGHTS
            .get_metric_with_label_values(&[&participant.to_string()])
            .map(|gauge| gauge.set(height as i64))
        {
            tracing::error!("Could not submit indexer height metric: {}", e);
        }
    }

    pub fn get_heights(&self) -> HashMap<ParticipantId, u64> {
        self.heights
            .iter()
            .map(|(participant, height)| {
                (
                    *participant,
                    height.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
            .collect()
    }
}

/// A tracker serves one participant set, so its series must not outlive it.
impl Drop for IndexerHeightTracker {
    fn drop(&mut self) {
        metrics::PEERS_INDEXER_HEIGHTS.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::core::Collector;
    use serial_test::serial;

    fn series_count() -> usize {
        metrics::PEERS_INDEXER_HEIGHTS
            .collect()
            .iter()
            .map(|family| family.get_metric().len())
            .sum()
    }

    #[test]
    #[serial(peers_indexer_heights)]
    #[expect(non_snake_case)]
    fn indexer_height_tracker__should_remove_every_series_when_dropped() {
        // Given
        let participants = [0, 1, 2].map(ParticipantId::from_raw);
        let tracker = IndexerHeightTracker::new(&participants);
        for participant in participants {
            tracker.set_height(participant, 100);
        }
        assert_eq!(series_count(), participants.len());

        // When
        drop(tracker);

        // Then
        assert_eq!(series_count(), 0);
    }
}
