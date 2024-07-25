use mpc_contract::config::ProtocolConfig;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use super::triple::{TripleId, TripleManager};

/// Amount of time to wait before we can say that the protocol is stuck.
const STUCK_TIMEOUT_THRESHOLD: Duration = Duration::from_secs(120);

/// While being stuck, report that the node is stuck every interval. This should not be higher
/// than STUCK_TIMEOUT_THRESHOLD due to how they are currently coupled in the following code.
const STUCK_REPORT_INTERVAL: Duration = Duration::from_secs(90);

pub struct StuckMonitor {
    triple_manager: Arc<RwLock<TripleManager>>,
    last_checked_triples: HashSet<TripleId>,
    last_changed_timestamp: Instant,
    stuck_interval_timestamp: Instant,
}

impl StuckMonitor {
    pub async fn new(triple_manager: &Arc<RwLock<TripleManager>>) -> Self {
        Self {
            triple_manager: triple_manager.clone(),
            last_checked_triples: triple_manager
                .read()
                .await
                .triples
                .keys()
                .cloned()
                .collect(),
            last_changed_timestamp: Instant::now(),
            stuck_interval_timestamp: Instant::now(),
        }
    }

    /// Check if the triples has changed or not. If they have not changed for a long time, then we
    /// will report that the protocol is stuck.
    ///
    /// Returns `true` if the protocol is stuck.
    pub async fn check(&mut self, cfg: &ProtocolConfig) -> bool {
        let triple_manager = self.triple_manager.read().await;
        let latest_triples: HashSet<_> = triple_manager.triples.keys().cloned().collect();
        if triple_manager.has_min_triples(cfg) {
            drop(triple_manager);
            self.reset(latest_triples);
            return false;
        }

        let diff = latest_triples
            .difference(&self.last_checked_triples)
            .collect::<HashSet<_>>();
        if !diff.is_empty() {
            drop(triple_manager);
            self.reset(latest_triples);
            return false;
        }

        if self.last_changed_timestamp.elapsed() >= STUCK_TIMEOUT_THRESHOLD
            && self.stuck_interval_timestamp.elapsed() >= STUCK_REPORT_INTERVAL
        {
            self.stuck_interval_timestamp = Instant::now();
            tracing::warn!(
                ?triple_manager,
                "protocol is stuck for the last {} seconds",
                self.last_changed_timestamp.elapsed().as_secs(),
            );
            return true;
        }

        false
    }

    fn reset(&mut self, latest_triples: HashSet<TripleId>) {
        self.last_checked_triples = latest_triples;
        self.last_changed_timestamp = Instant::now();
    }
}
