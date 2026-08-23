use std::{
    collections::{HashMap, hash_map::Entry as HashMapEntry},
    hash::Hash,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Suppress,
    Emit { suppressed: u64 },
}

#[derive(Debug)]
struct Entry {
    last_emit: Instant,
    last_seen: Instant,
    suppressed: u64,
}

struct State<K> {
    entries: HashMap<K, Entry>,
    last_cleanup: Instant,
}

pub struct Deduplicator<K> {
    state: Mutex<State<K>>,
    // Minimum time key stays suppressed
    interval: Duration,
    // Time an entry is valid for before eligible for cleanup
    ttl: Duration,
    // Maximum number of entries to track
    max_entries: usize,
}

impl<K> Deduplicator<K>
where
    K: Eq + Hash + Clone,
{
    pub fn new(interval: Duration, ttl: Duration, max_entries: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::with_capacity(max_entries),
                last_cleanup: Instant::now(),
            }),
            interval,
            ttl,
            max_entries,
        }
    }

    pub fn check(&self, key: &K, now: Instant) -> (Decision, Vec<(K, u64)>) {
        // Poisoning is not critical just for log suppression, ignore and continue, deliberate.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut dropped = Vec::new();

        if now.duration_since(state.last_cleanup) >= self.ttl {
            let ttl = self.ttl;
            let stale_keys: Vec<K> = state
                .entries
                .iter()
                .filter(|(_, entry)| now.duration_since(entry.last_seen) >= ttl)
                .map(|(k, _)| k.clone())
                .collect();
            for k in stale_keys {
                if let Some(entry) = state.entries.remove(&k)
                    && entry.suppressed > 0
                {
                    dropped.push((k, entry.suppressed));
                }
            }
            state.last_cleanup = now;
        }

        if !state.entries.contains_key(key) && state.entries.len() >= self.max_entries {
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(oldest_key) = oldest
                && let Some(entry) = state.entries.remove(&oldest_key)
                && entry.suppressed > 0
            {
                dropped.push((oldest_key, entry.suppressed));
            }
        }

        let decision = match state.entries.entry(key.clone()) {
            HashMapEntry::Vacant(v) => {
                v.insert(Entry {
                    last_emit: now,
                    last_seen: now,
                    suppressed: 0,
                });
                Decision::Emit { suppressed: 0 }
            }
            HashMapEntry::Occupied(mut o) => {
                let entry = o.get_mut();
                entry.last_seen = now;
                if now.duration_since(entry.last_emit) < self.interval {
                    entry.suppressed = entry.suppressed.saturating_add(1);
                    Decision::Suppress
                } else {
                    let suppressed = entry.suppressed;
                    entry.suppressed = 0;
                    entry.last_emit = now;
                    Decision::Emit { suppressed }
                }
            }
        };

        (decision, dropped)
    }

    pub fn reset(&self, key: &K) {
        // Poisoning is not critical just for log suppression, ignore and continue, deliberate.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.entries.remove(key);
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::log_dedup::{Decision, Deduplicator};
    use std::time::{Duration, Instant};

    #[test]
    fn deduplicator__should_emit() {
        // Given a new deduplicator
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_millis(50), Duration::from_secs(1), 10);
        // When / Then the first check is always emitted
        assert_eq!(
            dedup.check(&"test", now).0,
            Decision::Emit { suppressed: 0 }
        );
    }

    #[test]
    fn deduplicator__should_suppress() {
        // Given a new deduplicator with an event already emitted
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_millis(200), Duration::from_secs(1), 10);
        assert_eq!(
            dedup.check(&"test", now).0,
            Decision::Emit { suppressed: 0 }
        );
        // When the same event occurs several times within the interval
        // Then it is suppressed
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(50)).0,
            Decision::Suppress
        );
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(100)).0,
            Decision::Suppress
        );
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(150)).0,
            Decision::Suppress
        );
    }

    #[test]
    fn deduplicator__should_emit_suppression_count() {
        // Given a new deduplicator with an event already emitted
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_millis(30), Duration::from_secs(1), 10);
        assert_eq!(
            dedup.check(&"test", now).0,
            Decision::Emit { suppressed: 0 }
        );
        // When the same event occurs several times within the TTL and before the interval
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(5)).0,
            Decision::Suppress
        );
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(10)).0,
            Decision::Suppress
        );
        // Then the next identical event following the interval but before thr TTL gets emitted with the suppressed count
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(50)).0,
            Decision::Emit { suppressed: 2 }
        );
    }

    #[test]
    fn deduplicator__should_cleanup_stale_entries() {
        // Given a new deduplicator with an event already emitted
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_millis(10), Duration::from_millis(30), 10);
        assert_eq!(
            dedup.check(&"test", now).0,
            Decision::Emit { suppressed: 0 }
        );
        // When the event becomes stale by crossing the TTL
        // Then the entry should have been cleaned up as stale and becomes fresh again.
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(50)).0,
            Decision::Emit { suppressed: 0 }
        );
    }

    #[test]
    fn deduplicator__should_evict_on_max_entries() {
        // Given a deduplicator only accepting 2 entries.
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_millis(10), Duration::from_millis(10), 2);
        // When entries are added that exceed max_entries
        assert_eq!(
            dedup.check(&"one", now + Duration::from_millis(1)).0,
            Decision::Emit { suppressed: 0 }
        );
        assert_eq!(
            dedup.check(&"two", now + Duration::from_millis(2)).0,
            Decision::Emit { suppressed: 0 }
        );
        assert_eq!(
            dedup.check(&"three", now + Duration::from_millis(3)).0,
            Decision::Emit { suppressed: 0 }
        );
        // Then they get evicted and present as new entries again
        assert_eq!(
            dedup.check(&"one", now + Duration::from_millis(4)).0,
            Decision::Emit { suppressed: 0 }
        );
        assert_eq!(
            dedup.check(&"two", now + Duration::from_millis(5)).0,
            Decision::Emit { suppressed: 0 }
        );
    }

    #[test]
    fn deduplicator__should_emit_after_reset() {
        // Given a deduplication and event within the TTL.
        let now = Instant::now();
        let dedup = Deduplicator::new(Duration::from_secs(2), Duration::from_millis(500), 10);
        assert_eq!(
            dedup.check(&"test", now).0,
            Decision::Emit { suppressed: 0 }
        );
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(100)).0,
            Decision::Suppress
        );
        // When reset
        dedup.reset(&"test");
        // Then next identical event will be a new log that is emitted
        assert_eq!(
            dedup.check(&"test", now + Duration::from_millis(200)).0,
            Decision::Emit { suppressed: 0 }
        );
    }
}
