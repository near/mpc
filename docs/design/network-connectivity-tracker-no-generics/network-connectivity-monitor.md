# Network Connectivity Monitor

## Background

The multi party computation (MPC) system we develop and maintain runs threshold cryptography protocols. These protocols may not require all nodes in an MPC cluster to be live, but may succeed if only a subset of those nodes are live.

A lot of threshold cryptography protocols are split into two computation phases. In a _preprocessing phase_, participants jointly compute correlated material (e.g. triples or presignatures), which is then consumed in a subsequent _online phase_.

This split keeps the _online phase_ short, reducing latency and allows to front-load heavy computations during idle periods.

One caveat is that currently, and to guarantee security for some of these protocols, we require all participants in a computation to have live connections with one another.

Unfortunately, our system currently does not provide our nodes with the means to have a view of the MPC cluster's connectivity state. Right now, the leader of a computation selects participants for said computation based on a simple local view. If the leader can connect with the participants, it assumes that the participants will be able to connect with each other.

This is not an assumption that will be upheld. In production, we have now, multiple times, observed that connectivity is not uniform in the network. There were instances where two peers couldn't establish a stable connection, but those peers didn't have connectivity issues with any of the other nodes.
Additionally, connection quality is **not symmetric**. The link `A --> B` might be perfectly fine, while on `B --> A`, packets arrive late and computations time out.

To fix these issues, this document, together with [Network Connectivity Consumers and Publishers](./network-connectivity-consumer-publishers.md) and [Network Connectivity Link Observations](./network-connectivity-link-observations.md), outlines the design for components that will allow MPC nodes to have a better understanding of the network connections inside the MPC cluster.

## Design

The design is broken into three orthogonal parts:
- [Network Connectivity Consumers and Publishers](./network-connectivity-consumer-publishers.md) is focused on the **consumers** in the network. It explores four different components of the MPC node, that require an understanding of the network connectivity graph. It aims to identify appropriate interfaces and data structures that are useful to these components, and explains how each of those can be derived by combining two views:
    - a graph, presenting a current view of _established network connections_ in the MPC cluster
    - a current view of the _indexer block heights_ each peer has last reported as processed. This is necessary, because in our system, an MPC node cannot simply be considered "live", just because it has good connections with its peers. Each node also needs a current view of the NEAR blockchain.
- [Network Connectivity Link Observations](./network-connectivity-link-observations.md) contains a proposal on how the indexer height data, which our MPC nodes are currently gossiping, can be used to **derive qualitative statements** about the connection between a given pair of nodes in the cluster.
- The remainder of this document explores a **Network Connectivity Monitor** component, whose responsibility it is to process data that allows one to make conclusions about liveness of nodes. Currently, that entails two responsibilities:
    - it needs to keep an up to date view of the last processed _indexer block height_ by each peer;
    - it needs to maintain a current view of _established network connections_.

  It does so by aggregating data from producers and sharing the two views above with the components described in [Network Connectivity Consumers and Publishers](./network-connectivity-consumer-publishers.md).

The two views are:

```rust
/// Mapping each node in the cluster to its last reported indexer height
pub struct FirstHandIndexerHeights {
    heights: NonEmptyBTreeMap<ParticipantId, ReportedIndexerHeight>,
}

/// A current view of established connections. If an edge is not present, it means the connection is not bidirectionally established (i.e. broken in one or both directions).
pub struct EstablishedConnections {
    connections: AdjacencyMatrix<ParticipantId, ConnectionStatus, UndirectedEdge<ParticipantId>>,
}
```

Below is an overview of the data flow:

```mermaid
flowchart LR
    producers["Producers"]
    monitor["ConnectivityMonitor:<br/>derives link observations,<br/>tracks links and connections"]
    downstream["components described in<br/>Consumers and Publishers"]

    producers -- "PeerReport" --> monitor
    monitor -- "EstablishedConnections" --> downstream
    monitor -- "FirstHandIndexerHeights" --> downstream
```

## Peer Reports and Producers

Terminology:
- a _peer report_ is a report containing information useful to derive verdicts about the reporter's liveness, and connections they have with their _peers_. Currently, we only support one peer report:
    - A peer's `IndexerHeightReport`, containing the block height the reporter's indexer has last processed, as well as the last reported indexer block height of each peer, who is bidirectionally connected to the reporter.

  Note that this report is broadcast once a second by every node in the cluster.
- a _producer_ is something that can produce a _peer report_. We have two sources of peer reports in the node, both of which will need to be taken into account for the node's network connectivity view:
    - the node's own indexer height broadcast task, which generates the nodes own `IndexerHeightReport`. It does so by:
        - inspecting the network layer and filtering for all participants that are currently bidirectionally connected to the node;
        - checking the latest indexer heights it has received from these nodes;
        - comparing those heights against its own, currently last processed indexer block height;
        - broadcasting that information to all its peers.
    - the network layer, which receives peer reports received from connected nodes.

```rust
pub enum PeerReport {
    IndexerHeightReport(IndexerHeightReport),
}

pub struct IndexerHeightReport {
    pub reporter: ParticipantId,
    // the reporter's own indexer height, under its own key, and the heights it last received from its peers
    pub indexer_heights: BTreeMap<ParticipantId, ReportedIndexerHeight>,
}

pub enum ReportedIndexerHeight {
    Unknown,
    Known(BlockHeight),
}
```

In the future, we may add new types of peer reports, such as results from echo-connection checks or pings.

## The `ConnectivityMonitor`

We need a component that can collect peer reports, process them, and update the two structs consumers care about (`EstablishedConnections` and `FirstHandIndexerHeights`). We call this component `ConnectivityMonitor`.

Roughly, data is processed as follows:
1. A `PeerReport` is sent to the `ConnectivityMonitor`.
2. If the `PeerReport` contains information about first hand indexer heights, the `ConnectivityMonitor` updates and **publishes** `FirstHandIndexerHeights`.
3. The `PeerReport` is converted to a series of **link observations** (`DerivedLinkObservation`), which are observations about directed **network links** `A --> B`.
4. Those `DerivedLinkObservation`s are then passed to a connection tracker (`ConnectionTracker`), which registers the new observation and determines whether it has an impact on the **qualitative status of a network connection** (where, a connection `A <--> B` is derived from the links `A --> B` and `B --> A`).
5. The `ConnectionTracker` reports to the `ConnectivityMonitor` whether a connection status changed qualitatively (e.g. it got interrupted, or re-established, or the quality of the connection changed otherwise).
6. If a connection status changed, the `ConnectivityMonitor` **publishes** a new `EstablishedConnections` graph.

```mermaid
flowchart LR
    producers["producers"]
    monitor["ConnectivityMonitor"]
    tracker["ConnectionTracker"]
    downstream["components described in<br/>Consumers and Publishers"]

    producers -- "(1) PeerReport" --> monitor
    monitor -- "(2) FirstHandIndexerHeights" --> downstream
    monitor -- "(3, 4) DerivedLinkObservation,<br/>one per link" --> tracker
    tracker -- "(5) ConnectionChanged" --> monitor
    monitor -- "(6) EstablishedConnections" --> downstream
```

```rust
struct ConnectivityMonitor {
    // state
    clock: Clock,
    // for periodically publishing link reports (metrics)
    report_interval: Duration,

    // the connection tracker, tracking connection quality and link observations
    connection_tracker: ConnectionTracker,

    // everything we receive from other components
    peer_reports: mpsc::Receiver<PeerReport>,

    // everything we send to other components
    /// as soon as a connection changes its status, this is updated
    connections: watch::Sender<Arc<EstablishedConnections>>,
    /// the indexer heights we have for ourselves and the peers, updated with every `PeerReport`
    heights: watch::Sender<FirstHandIndexerHeights>,
    /// updated every report_interval, for metrics.
    link_statuses: watch::Sender<LinkStatuses>,
}

```

### Interface of `ConnectivityMonitor`

The `ConnectivityMonitor` is able to process peer reports:
```rust
impl ConnectivityMonitor {
    /// Returns the monitor, which the caller has to run, and its channels.
    pub fn new(
        clock: Clock,
        report_interval: Duration,
        nodes: &NonEmptyBTreeSet<ParticipantId>,
        report_buffer_size: NonZeroUsize,
    ) -> Result<(Self, ConnectivityMonitorHandles), TooManyNodesError>;

    /// Runs until `cancellation_token` is cancelled or every sender of peer reports is gone.
    pub async fn run(mut self, cancellation_token: CancellationToken);
    fn apply_and_publish(&mut self, report: PeerReport);
}
```

`new` returns the monitor together with its handles:

```rust
/// The channels of a `ConnectivityMonitor` that the other components use.
pub struct ConnectivityMonitorHandles {
    // producers send their peer reports here
    pub peer_reports: mpsc::Sender<PeerReport>,
    pub connections: watch::Receiver<Arc<EstablishedConnections>>,
    // the times stored in `connections` are from this clock, so ask them with its `now`
    pub clock: Clock,
    pub heights: watch::Receiver<FirstHandIndexerHeights>,
    pub link_statuses: watch::Receiver<LinkStatuses>,
}

/// The status of each link, keyed by its two nodes. For metrics.
pub struct LinkStatuses(BTreeMap<(ParticipantId, ParticipantId), LinkStatus>);
```

### Links, Connection Status and Link Observations

The `ConnectivityMonitor` works with the following types:
- The graphs index vertices by `ParticipantId`, which represents a node in the MPC cluster. In the future, we may want to use a more precise type, since a single participant could have multiple nodes (e.g. during migrations).
- `ConnectionStatus` is the status of a connection `A <--> B`.
- `LinkHistory` is the type used to track a link `A --> B` and its status.
- `LinkStatus` is the status of a link. It is what a `LinkHistory` reports about itself.
- A link observation is a `LinkObservation`, with one variant per kind of peer report. Currently, the only one is `IndexerHeightLag`, derived from the `IndexerHeightReport`. In the future, we may add more peer reports and more observation types (such as results from echo-connection checks).

The connection status, link, link status and link observation types are defined in [Network Connectivity Link Observations](./network-connectivity-link-observations.md). Here, we only list what the `ConnectivityMonitor` and the consumers use of them:
- The `LinkHistory` reports its `LinkStatus` (the `LinkStatuses` above), which helps determine whether an observation led to a link status change.
```rust
impl LinkHistory {
    pub fn link_status(&self) -> LinkStatus;
}
```
- The `LinkHistory` processes the link observations that the producers want the connectivity monitor to process. Additionally, it reports whether an observation led to a new link status:
```rust
impl LinkHistory {
    /// Reports the new status in case it changed.
    pub fn update_with_observation(
        &mut self,
        observation: LinkObservation,
        at: Instant,
    ) -> LinkStatusChange;
}

pub enum LinkStatusChange {
    // status changed, contained is the new status
    Changed(LinkStatus),
    Unchanged,
}
```
- The `ConnectionStatus` for a connection `A <--> B` is inferred from the `LinkStatus` of each of the two links `A --> B` and `B --> A`:
```rust
impl LinkStatus {
    /// The connection that the two links between a pair of nodes add up to. A link is `None`
    /// while it has no observations.
    pub fn infer_connection(
        a: Option<Self>,
        b: Option<Self>,
    ) -> InferredConnection;
}

/// What two link statuses add up to: a connection with a status, or no connection.
pub enum InferredConnection {
    Established(ConnectionStatus),
    NotEstablished,
}
```
- The `ConnectionStatus` makes qualitative statements about a connection's quality (c.f. [Network readiness publisher](./network-connectivity-consumer-publishers.md#network-readiness-publisher)):
```rust
impl ConnectionStatus {
    /// can be used to estimate whether a connection is sufficient for a specific computation duration
    pub fn connection_supports(
        &self,
        duration: ComputationDuration,
        now: Instant,
    ) -> ComputationSupported;
}

pub enum ComputationSupported {
    Yes,
    No,
}

// to be refined. Triples need about 23 seconds, signatures about 2 seconds.
pub enum ComputationDuration {
    Any,
    Seconds,
    HalfMinute,
}
```
- And lastly, the link observations are derived from the provided `PeerReport`:
```rust
impl PeerReport {
    /// The link observations derived from this report.
    pub fn derive_link_observations(
        &self,
        context: &ObservationContext<'_>,
    ) -> Vec<DerivedLinkObservation>;
}

pub struct DerivedLinkObservation {
    pub link: DirectedEdge<ParticipantId>,
    pub observation: LinkObservation,
}

pub enum LinkObservation {
    IndexerHeightLag(IndexerHeightLag),
}

pub struct ObservationContext<'a> {
    pub first_hand_indexer_heights: &'a FirstHandIndexerHeights,
}

```

```mermaid
flowchart LR
    report["PeerReport"]
    observation["a series of<br/>DerivedLinkObservations"]
    link["link status,<br/>one per link"]
    connection["connection status,<br/>one per connection"]
    support["ComputationSupported"]

    report -- "derive_link_observations" --> observation
    observation -- "update_with_observation" --> link
    link -- "infer_connection" --> connection
    connection -- "connection_supports" --> support
```

### `ConnectionTracker`

The `ConnectionTracker` is the component responsible for maintaining the `EstablishedConnections` graph, which the consumers rely on.
Besides the undirected `EstablishedConnections` graph, it keeps a directed graph to track network links `A --> B`. This directed graph is updated with every new link observation.

```rust
pub struct ConnectionTracker {
    // a link is a directed connection node A --> B,
    // each link is measured, such that we can infer link quality from the measurements.
    link_measurements: LinkMeasurements,
    // a connection is a bidirectional connection `A <--> B`.
    // It is as good as the worse of the two links `A --> B` and `B --> A`
    established_connections: EstablishedConnections,
}

pub struct LinkMeasurements {
    measurements: AdjacencyMatrix<ParticipantId, LinkHistory, DirectedEdge<ParticipantId>>,
}
```

The interface of the `ConnectionTracker` reflects what it does:
- it processes a link observation `A --> B` via `update_with_observation` and reports whether the observation changed the qualitative verdict about connection `A <--> B`;
```rust
impl ConnectionTracker {
    // this is to process a new link observation
    pub fn update_with_observation(
        &mut self,
        observation: DerivedLinkObservation,
        now: Instant,
    ) -> Result<ConnectionChanged, UnknownNodeError<ParticipantId>> {...}
}

/// Whether an update changed the connection it was applied to.
pub enum ConnectionChanged {
    Yes,
    No,
}
```
- it provides a view of the current connection status via `established_connections`.
```rust
impl ConnectionTracker {
    // this returns the currently established connections
    pub fn established_connections(&self) -> &EstablishedConnections
}
```
- it additionally offers a constructor and a link status report, which may be used for improving observability (i.e. metrics), but is not assumed to be of interest to any of the consumers:
```rust
impl ConnectionTracker {
    // constructor, taking as input the current network participants
    pub fn new(nodes: &NonEmptyBTreeSet<ParticipantId>) -> Result<Self, TooManyNodesError>
    // this is for metrics only, we may want to periodically track individual link statuses
    pub fn report_link_statuses(&self) -> LinkStatuses {..}
}
```

## Todo

This design assumes that every peer sends an `IndexerHeightReport`; peers on older network protocol versions do not. We therefore need to bump the lowest supported network protocol version, and can then remove the deprecated code for supporting older protocol versions.


