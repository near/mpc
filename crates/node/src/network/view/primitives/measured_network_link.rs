//! This file contains generic structs that can be used to measure network link quality.
//!
//! For any given link, we can track recent observations and allow to infer the network link status
//! form them.
//!
//! A type `T` used to measure link quality should be possible to aggreagate via Aggregate
//!
//! For example:
//! ```
//! enum OnlineStatus {
//!     Online,
//!     Offline
//! }
//!
//! // the observations for the link: we periodically ping
//! struct Ping(u64);
//!
//! type PingStatus = MeasurdeLinks<OnlineStatus, Ping>::new();
//! // show how it's done...
//! ```

use std::collections::VecDeque;
use std::num::NonZeroUsize;

/// A link together with its recent observations and the status inferred from them.
///
/// Invariant: `status == recent.infer()`. It is cached because it is read far more often
/// than it is written, and because inferring link status may be relatively expensive.
#[derive(Debug, Clone)]
pub struct MeasuredLink<S, T> {
    status: LinkStatus<S>,
    recent: RecentObservations<T>,
}

impl<S, T> MeasuredLink<S, T> {
    pub fn new(window: NonZeroUsize) -> Self {
        Self {
            status: LinkStatus::Unknown,
            recent: RecentObservations::new(window),
        }
    }

    pub fn status(&self) -> &LinkStatus<S> {
        &self.status
    }
}

impl<S: InferLinkStatus<T>, T> MeasuredLink<S, T> {
    pub fn add_observation(&mut self, observation: LinkObservation<T>) {
        self.recent.push_back(observation);
        self.status = S::infer_link_status(&self.recent);
    }
}

/// Turns a link's recent observations into a status.
/// Implementors decide when a link counts as absent and how observations are summarised.
/// good observations are summarised.
pub trait InferLinkStatus<T>: Sized {
    fn infer_link_status(observations: &RecentObservations<T>) -> LinkStatus<Self>;
}

/// Current belief about a link, inferred from recent [`LinkObservation`]s.
///
/// `Unknown` is never observed, only inferred: it means we have no observations at all,
/// either because the node just started or because the peer speaks an older protocol that
/// never reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkStatus<S> {
    #[default]
    Unknown,
    Present(S),
    Absent,
}

impl<S: PartialOrd> LinkStatus<S> {
    /// Whether this link may be used for a computation.
    pub fn usable(&self, threshold: &S) -> bool {
        match self {
            LinkStatus::Unknown => true,
            LinkStatus::Present(s) => s <= threshold,
            LinkStatus::Absent => false,
        }
    }
}

/// A ring-buffer for recent observations.
#[derive(Debug, Clone)]
pub struct RecentObservations<T> {
    buffer_size: NonZeroUsize,
    samples: VecDeque<LinkObservation<T>>,
}

impl<T> RecentObservations<T> {
    pub fn new(buffer_size: NonZeroUsize) -> Self {
        Self {
            buffer_size,
            samples: VecDeque::with_capacity(buffer_size.get()),
        }
    }

    pub fn push_back(&mut self, observation: LinkObservation<T>) {
        if self.samples.len() == self.buffer_size.get() {
            self.samples.pop_front();
        }
        self.samples.push_back(observation);
    }
    pub fn newest(&self) -> Option<&LinkObservation<T>> {
        self.samples.back()
    }
    pub fn newest_first(&self) -> impl Iterator<Item = &LinkObservation<T>> {
        self.samples.iter().rev()
    }
}

/// One observation of a link: unreachable, or reachable with a measurement `T`.
/// For example:
/// struct enum OnlineStatus = Online/Offline;
/// type OnlineStatus = LinkObservation<OnlineStatus>;
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
