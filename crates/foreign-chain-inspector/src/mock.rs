//! Scripted test doubles for the network fingerprint probe.
//!
//! Scripted delays are virtual timers under `#[tokio::test(start_paused = true)]`, so retry,
//! backoff and timeout run in microseconds. Never mix paused time with a real socket (httpmock,
//! tonic): the runtime advances the clock while the socket is silent and fires the timeout first.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector};

/// One scripted attempt. Outcomes are built per attempt because [`ForeignChainInspectionError`]
/// is not `Clone`.
#[derive(Debug)]
pub enum ScriptedReply {
    /// Keep `fingerprint` under [`NetworkFingerprint`]'s length cap, or it is truncated on the
    /// way out.
    Answer {
        delay: Duration,
        fingerprint: String,
    },
    /// [`FanOut`](crate::FanOut) retries a transient failure.
    TransientFailure { delay: Duration },
    /// [`FanOut`](crate::FanOut) does not retry a refusal.
    Refusal { delay: Duration },
    /// Never resolves; only the caller's timeout ends the attempt.
    Hang,
}

/// Answers from a queue of [`ScriptedReply`]s and panics past the end of the script, so an
/// unexpected extra attempt fails loudly. Clones share the queue and the counter, so give each
/// provider its own and keep a clone for [`ScriptedInspector::calls`].
#[derive(Clone)]
pub struct ScriptedInspector {
    script: Arc<Mutex<VecDeque<ScriptedReply>>>,
    calls: Arc<AtomicUsize>,
}

impl ScriptedInspector {
    pub fn new(replies: impl IntoIterator<Item = ScriptedReply>) -> Self {
        Self {
            script: Arc::new(Mutex::new(replies.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NetworkFingerprintInspector for ScriptedInspector {
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .script
            .lock()
            .expect("script mutex poisoned")
            .pop_front()
            .expect("call beyond the script");
        match reply {
            ScriptedReply::Answer { delay, fingerprint } => {
                tokio::time::sleep(delay).await;
                Ok(NetworkFingerprint::new(fingerprint))
            }
            ScriptedReply::TransientFailure { delay } => {
                tokio::time::sleep(delay).await;
                Err(ForeignChainInspectionError::RpcRequestFailed(
                    "scripted transient failure".to_string(),
                ))
            }
            ScriptedReply::Refusal { delay } => {
                tokio::time::sleep(delay).await;
                Err(ForeignChainInspectionError::RpcRequestRejected(
                    "scripted refusal".to_string(),
                ))
            }
            ScriptedReply::Hang => std::future::pending().await,
        }
    }

    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(fingerprint)
    }
}
