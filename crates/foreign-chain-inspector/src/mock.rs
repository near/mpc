//! Test doubles for the Foreign Tx Inspectors.
//!
//! Use `#[tokio::test(start_paused = true)]` if test case simulates network latency.
//! Never use with real sockets, tokio paused clock will fire timeouts instantly.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector};

#[derive(Debug)]
pub enum MockReply {
    Answer {
        delay: Duration,
        fingerprint: String,
    },
    Fail {
        delay: Duration,
        error: ForeignChainInspectionError,
    },
    /// Never resolves
    Hang,
}

impl MockReply {
    pub fn fail(delay: Duration, error: ForeignChainInspectionError) -> Self {
        Self::Fail { delay, error }
    }

    pub fn transient(delay: Duration) -> Self {
        Self::fail(
            delay,
            ForeignChainInspectionError::RpcRequestFailed("mock transient failure".to_string()),
        )
    }

    pub fn refusal(delay: Duration) -> Self {
        Self::fail(
            delay,
            ForeignChainInspectionError::RpcRequestRejected("mock refusal".to_string()),
        )
    }
}

/// Answers from a queue of [`MockReply`]s; panics on a call past the end of the queue.
#[derive(Clone)]
pub struct MockInspector {
    replies: Arc<Mutex<VecDeque<MockReply>>>,
    calls: Arc<AtomicUsize>,
}

impl MockInspector {
    pub fn new(replies: impl IntoIterator<Item = MockReply>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NetworkFingerprintInspector for MockInspector {
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .replies
            .lock()
            .expect("replies mutex poisoned")
            .pop_front()
            .expect("call beyond the queued replies");
        match reply {
            MockReply::Answer { delay, fingerprint } => {
                tokio::time::sleep(delay).await;
                Ok(NetworkFingerprint::new(fingerprint))
            }
            MockReply::Fail { delay, error } => {
                tokio::time::sleep(delay).await;
                Err(error)
            }
            MockReply::Hang => std::future::pending().await,
        }
    }

    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(fingerprint)
    }
}
