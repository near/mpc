//! Scripted test doubles for the network fingerprint probe.
//!
//! Under `#[tokio::test(start_paused = true)]` every scripted delay is a virtual timer, so
//! retry, backoff and timeout behavior runs deterministically and in microseconds of wall
//! time. Never combine paused time with a real socket (httpmock, tonic): the runtime
//! advances the clock automatically while the socket is silent, firing timeouts before any
//! real response can land.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector};

/// One scripted attempt: a virtual delay, then an outcome. Outcomes are constructed fresh
/// per attempt because [`ForeignChainInspectionError`] is not `Clone`.
#[derive(Debug)]
pub enum ScriptedReply {
    /// Answer `fingerprint` after `delay`. Keep the string under
    /// [`NetworkFingerprint`]'s length cap, or it is truncated on the way out.
    Answer {
        delay: Duration,
        fingerprint: String,
    },
    /// A transient failure ([`ForeignChainInspectionError::RpcRequestFailed`]) after
    /// `delay`; [`FanOut`](crate::FanOut) retries it.
    TransientFailure { delay: Duration },
    /// A refusal ([`ForeignChainInspectionError::RpcRequestRejected`]) after `delay`;
    /// [`FanOut`](crate::FanOut) does not retry it.
    Refusal { delay: Duration },
    /// Never resolves; only the caller's timeout ends the attempt.
    Hang,
}

/// A [`NetworkFingerprintInspector`] that answers each call from a queue of
/// [`ScriptedReply`]s and panics on a call beyond the script, so an unexpected extra
/// attempt fails loudly. Clones share the queue and the call counter —
/// [`FanOut`](crate::FanOut) clones its inspector into the task it spawns for each
/// provider — so use one instance per provider and keep a clone in the test for
/// [`ScriptedInspector::calls`].
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

    /// How many attempts reached this inspector so far.
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

    /// Identity: tests script the exact canonical string they assert.
    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(fingerprint)
    }
}
