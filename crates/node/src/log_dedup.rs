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
    interval: Duration,
    stale_after: Duration,
}

impl<K> Deduplicator<K>
where
    K: Eq + Hash + Clone,
{
    pub fn new(interval: Duration, stale_after: Duration) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            interval,
            stale_after,
        }
    }

    pub fn check(&self, key: &K) -> Decision {
        let now = Instant::now();
        // Poisoning is not critical just for log suppression, ignore and continue, deliberate.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if now.duration_since(state.last_cleanup) >= self.stale_after {
            state
                .entries
                .retain(|_, entry| now.duration_since(entry.last_seen) < self.stale_after);
            state.last_cleanup = now;
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
