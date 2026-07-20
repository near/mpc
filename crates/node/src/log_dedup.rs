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
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            interval,
            ttl,
            max_entries,
        }
    }

    pub fn check(&self, key: &K) -> Decision {
        let now = Instant::now();
        // Poisoning is not critical just for log suppression, ignore and continue, deliberate.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if now.duration_since(state.last_cleanup) >= self.ttl {
            let ttl = self.ttl;
            state
                .entries
                .retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
            state.last_cleanup = now;
        }

        if !state.entries.contains_key(key) && state.entries.len() >= self.max_entries {
            if let Some(oldest_key) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(k, _)| k.clone())
            {
                state.entries.remove(&oldest_key);
            }
        }

        match state.entries.entry(key.clone()) {
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
                    entry.suppressed += 1;
                    return Decision::Suppress;
                }
                let suppressed = entry.suppressed;
                entry.suppressed = 0;
                entry.last_emit = now;
                Decision::Emit { suppressed }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_emission() {
        let dedup = Deduplicator::new(Duration::from_millis(50), Duration::from_secs(60), 10);
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 0 });
    }

    #[test]
    fn test_suppression() {
        let dedup = Deduplicator::new(Duration::from_millis(200), Duration::from_secs(60), 10);
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"test"), Decision::Suppress);
        assert_eq!(dedup.check(&"test"), Decision::Suppress);
        assert_eq!(dedup.check(&"test"), Decision::Suppress);
    }

    #[test]
    fn test_emission_suppression_count() {
        let dedup = Deduplicator::new(Duration::from_millis(30), Duration::from_secs(60), 10);
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"test"), Decision::Suppress);
        assert_eq!(dedup.check(&"test"), Decision::Suppress);
        sleep(Duration::from_millis(50));
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 2 });
    }

    #[test]
    fn test_stale_entry_cleanup() {
        let dedup = Deduplicator::new(Duration::from_millis(10), Duration::from_millis(30), 10);
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 0 });
        sleep(Duration::from_millis(50));
        // Entry should have been cleaned up as stale, so it looks fresh again.
        assert_eq!(dedup.check(&"test"), Decision::Emit { suppressed: 0 });
    }

    #[test]
    fn test_max_entries_eviction() {
        let dedup = Deduplicator::new(Duration::from_secs(60), Duration::from_secs(60), 2);
        assert_eq!(dedup.check(&"one"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"two"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"three"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"one"), Decision::Emit { suppressed: 0 });
        assert_eq!(dedup.check(&"two"), Decision::Emit { suppressed: 0 });
    }
}
