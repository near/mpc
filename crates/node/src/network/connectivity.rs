//! What this node knows about the network: which participants are connected, and how well.
//!
//! Participants gossip what they see of their peers. Observations about directed links are
//! derived from each such report, the two links between a pair of participants are combined into
//! the status of their connection, and computations are checked against those connections.
//!
//! - `graph`: edges over a fixed node set, with no network meaning.
//! - `health`: links, connections, and the tracker that derives connections from links. Generic
//!   over how a link is measured.
//! - `reports`: the reports all of this is built from, and the observations derived from them.
//!   A new kind of report goes here.
//! - `measurements`: link measurements, which turn observations into a link status. A new way
//!   of judging a link goes here.
//! - `monitor`: applies reports and publishes the result.
//!
//! # From a report to a connection
//!
//! Each step is one trait, implemented by the type the step starts from:
//!
//! | Step | Trait | Implemented by |
//! |---|---|---|
//! | report → observations, one per directed link | `DeriveLinkObservations` | the report |
//! | observation → link measurement | `UpdateLinkStatus<O>` | the link measurement |
//! | link measurement → link status | `ReportLinkStatus` | the link measurement |
//! | the two link statuses of a pair → connection, or none | `InferConnection` | the link status |
//! | connection → supports a computation? | `CheckComputationSupport` | the connection status |
//!
//! # Adding a link measurement
//!
//! A link measurement holds what has been measured about one directed link. It goes in
//! `measurements`, must be `Default` (a link before its first observation), and implements
//! `ReportLinkStatus` and, once per observation type `O` it takes in, `UpdateLinkStatus<O>`.
//!
//! Its link status type implements `InferConnection`, naming the connection status type. That
//! one implements `CheckComputationSupport`.
//!
//! # Adding a report
//!
//! The report type and the observation type derived from it go in `reports`. Then:
//! - implement `DeriveLinkObservations` for the report;
//! - add a variant for it to `PeerReport`;
//! - implement `ApplyPeerReport` for it on `ConnectivityMonitor`;
//! - implement `UpdateLinkStatus` for its observation on every link measurement that should use
//!   it.

mod errors;
pub mod first_hand_indexer_heights;
mod graph;
mod health;
pub mod local_network_view;
mod measurements;
mod monitor;
mod reports;

pub use graph::UndirectedEdge;
