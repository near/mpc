use std::cmp::max;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};

use near_contract_transport::{ObservedState, TransportError, WatchContractState};
use tokio::sync::watch;

use crate::tracking::AutoAbortTask;

/// A contract view kept current in a watch channel by a task the monitor owns; dropping the
/// monitor stops the task. Derefs to the receiver.
pub struct Monitor<U> {
    receiver: watch::Receiver<U>,
    /// `None` when another owner feeds the channel, as the fake indexer does.
    _task: Option<AutoAbortTask<()>>,
}

impl<U> Monitor<U>
where
    U: Clone + Debug + PartialEq + Send + Sync + 'static,
{
    /// Starts at `seed` and returns at once; the first successful read replaces it, and a source
    /// that keeps failing leaves it in place.
    pub fn seeded<S, F>(name: &'static str, seed: U, source: S, map: F) -> Self
    where
        S: WatchContractState + Send + 'static,
        S::ViewError: Debug,
        F: Fn(ObservedState<S::Value>) -> Option<U> + Send + 'static,
    {
        let (sender, receiver) = watch::channel(seed);
        let task = tokio::spawn(forward(name, source, sender, map));
        Self {
            receiver,
            _task: Some(task.into()),
        }
    }

    /// Returns once the source succeeded once, so the receiver never holds a placeholder. Fails
    /// only if the source closes first.
    pub async fn after_first_read<S, F>(
        name: &'static str,
        mut source: S,
        map: F,
    ) -> Result<Self, TransportError<S::ViewError>>
    where
        S: WatchContractState + Send + 'static,
        S::ViewError: Debug,
        F: Fn(ObservedState<S::Value>) -> Option<U> + Send + 'static,
    {
        let first = loop {
            match source.latest() {
                Ok(observed) => {
                    if let Some(value) = map(observed) {
                        break value;
                    }
                }
                Err(err) => tracing::error!(target: "mpc", name, ?err, "contract view failed"),
            }
            source.changed().await?;
        };
        Ok(Self::seeded(name, first, source, map))
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(receiver: watch::Receiver<U>) -> Self {
        Self {
            receiver,
            _task: None,
        }
    }
}

impl<U> Deref for Monitor<U> {
    type Target = watch::Receiver<U>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl<U> DerefMut for Monitor<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

async fn forward<S, U, F>(name: &'static str, mut source: S, sender: watch::Sender<U>, map: F)
where
    S: WatchContractState,
    S::ViewError: Debug,
    U: Debug + PartialEq,
    F: Fn(ObservedState<S::Value>) -> Option<U>,
{
    loop {
        match source.latest() {
            Ok(observed) => {
                if let Some(value) = map(observed) {
                    sender.send_if_modified(|current| {
                        if *current == value {
                            return false;
                        }
                        tracing::info!(target: "mpc", "{name} changed: {value:?}");
                        *current = value;
                        true
                    });
                }
            }
            Err(err) => tracing::error!(target: "mpc", name, ?err, "contract view failed"),
        }
        if let Err(err) = source.changed().await {
            tracing::error!(target: "mpc", name, ?err, "contract view subscription closed");
            return;
        }
    }
}

/// Two sources read as one: a change on either side is a change, and the latest value is the
/// pair, stamped with the later of the two heights. The sides poll independently, so the pair
/// can be transiently inconsistent; the next change corrects it.
pub(super) struct Zip<A, B>(pub(super) A, pub(super) B);

impl<A, B> WatchContractState for Zip<A, B>
where
    A: WatchContractState + Send,
    B: WatchContractState<ViewError = A::ViewError> + Send,
{
    type Value = (A::Value, B::Value);
    type ViewError = A::ViewError;

    fn latest(&mut self) -> Result<ObservedState<Self::Value>, TransportError<Self::ViewError>> {
        let a = self.0.latest()?;
        let b = self.1.latest()?;
        Ok(ObservedState {
            observed_at: max(a.observed_at, b.observed_at),
            value: (a.value, b.value),
        })
    }

    async fn changed(&mut self) -> Result<(), TransportError<Self::ViewError>> {
        tokio::select! {
            changed = self.0.changed() => changed,
            changed = self.1.changed() => changed,
        }
    }
}
