//! Generic measurement of network link quality: a [`MeasuredLink`] keeps a window of recent
//! [`LinkObservation`]s, and an [`InferLinkStatus`] implementation turns them into a
//! [`LinkStatus`].
//!
//! ```ignore
//! use std::num::NonZeroUsize;
//!
//! /// Round-trip time of one ping, in milliseconds.
//! struct Ping(u64);
//!
//! /// Round-trip time of the latest ping.
//! #[derive(Debug, PartialEq, PartialOrd)]
//! struct Latency(u64);
//!
//! impl InferLinkStatus<Ping> for Latency {
//!     fn infer_link_status(observations: &RecentObservations<Ping>) -> LinkStatus<Self> {
//!         match observations.newest() {
//!             LinkObservation::Present(Ping(ms)) => LinkStatus::Present(Latency(*ms)),
//!             LinkObservation::Absent => LinkStatus::Absent,
//!         }
//!     }
//! }
//!
//! let window = NonZeroUsize::new(3).unwrap();
//! let mut link: MeasuredLink<Latency, Ping> =
//!     MeasuredLink::new(window, LinkObservation::Present(Ping(20)));
//! assert_eq!(link.status(), &LinkStatus::Present(Latency(20)));
//! assert!(!link.status().is_absent_or_exceeds_threshold(&Latency(100)));
//!
//! link.add_observation(LinkObservation::Absent);
//! assert_eq!(link.status(), &LinkStatus::Absent);
//! ```

use std::collections::VecDeque;
use std::num::NonZeroUsize;

/// A link together with its recent observations and the status inferred from them.
///
/// Invariant: `status` is [`InferLinkStatus::infer_link_status`] of `recent_observations`. It is
/// cached because it is read far more often than written and inferring it may be expensive.
#[derive(Debug, Clone)]
pub struct MeasuredLink<S, T> {
    status: LinkStatus<S>,
    recent_observations: RecentObservations<T>,
}

impl<S, T> MeasuredLink<S, T> {
    pub fn status(&self) -> &LinkStatus<S> {
        &self.status
    }
}

impl<S: InferLinkStatus<T>, T> MeasuredLink<S, T> {
    pub fn new(window: NonZeroUsize, first_observation: LinkObservation<T>) -> Self {
        let recent_observations = RecentObservations::new(window, first_observation);
        let status = S::infer_link_status(&recent_observations);
        Self {
            status,
            recent_observations,
        }
    }

    pub fn add_observation(&mut self, observation: LinkObservation<T>) {
        self.recent_observations.push_back(observation);
        self.status = S::infer_link_status(&self.recent_observations);
    }
}

/// Turns a link's recent observations into a status.
/// Implementors decide when a link counts as absent and how present observations are summarised.
pub trait InferLinkStatus<T>: Sized {
    fn infer_link_status(observations: &RecentObservations<T>) -> LinkStatus<Self>;
}

/// Current belief about a link, inferred from recent [`LinkObservation`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus<S> {
    Present(S),
    Absent,
}

impl<S: PartialOrd> LinkStatus<S> {
    /// A status equal to `threshold` does not exceed it.
    pub fn is_absent_or_exceeds_threshold(&self, threshold: &S) -> bool {
        match self {
            LinkStatus::Present(s) => threshold < s,
            LinkStatus::Absent => true,
        }
    }
}

/// A ring-buffer for recent observations.
/// Invariant: this is never empty
#[derive(Debug, Clone)]
pub struct RecentObservations<T> {
    buffer_size: NonZeroUsize,
    samples: VecDeque<LinkObservation<T>>,
}

impl<T> RecentObservations<T> {
    pub fn new(buffer_size: NonZeroUsize, observation: LinkObservation<T>) -> Self {
        let mut samples = VecDeque::with_capacity(buffer_size.get());
        samples.push_back(observation);
        Self {
            buffer_size,
            samples,
        }
    }

    pub fn push_back(&mut self, observation: LinkObservation<T>) {
        if self.samples.len() == self.buffer_size.get() {
            self.samples.pop_front();
        }
        self.samples.push_back(observation);
    }
    pub fn newest(&self) -> &LinkObservation<T> {
        self.samples
            .back()
            .expect("by construction, recent observations is never empty")
    }
    pub fn newest_first(&self) -> impl Iterator<Item = &LinkObservation<T>> {
        self.samples.iter().rev()
    }
}

/// One observation of a link: unreachable, or reachable with a measurement `T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkObservation<T> {
    Present(T),
    Absent,
}

impl<T> LinkObservation<T> {
    pub fn present(&self) -> Option<&T> {
        match self {
            LinkObservation::Present(t) => Some(t),
            LinkObservation::Absent => None,
        }
    }
}

// todo: tests
