use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

use mpc_node_config::MAX_INDEXER_HEIGHT_DIFF;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::network::view::network_view::{Connection, ConnectionState, NetworkView};
use crate::primitives::{ConnectedPeersInfo, ParticipantId, PeerConnectedPeersInfo};

pub enum NetworkViewUpdate {
    ConnectedPeersInfo(PeerConnectedPeersInfo),
    /// A participant's own indexer height: ours from the indexer, a legacy peer's from its
    /// `IndexerHeight` message.
    IndexerHeight {
        participant: ParticipantId,
        height: u64,
    },
    /// The participants the transport is bidirectionally connected to.
    ConnectedPeers(BTreeSet<ParticipantId>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineStatus {
    Online,
    Offline,
}

/// an unordered pair of participant ids. Always uset he constructor for this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetworkLink(ParticipantId, ParticipantId);

impl NetworkLink {
    pub fn new(a: ParticipantId, b: ParticipantId) -> Self {
        if a <= b { Self(a, b) } else { Self(b, a) }
    }

    pub fn contains(&self, id: ParticipantId) -> bool {
        self.0 == id || self.1 == id
    }

    pub fn other(&self, id: ParticipantId) -> Option<ParticipantId> {
        if self.0 == id {
            Some(self.1)
        } else if self.1 == id {
            Some(self.0)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkGraph {
    pub offline_participants: BTreeSet<ParticipantId>,
    pub offline_links: BTreeSet<NetworkLink>,
}

trait CliqueStatus {
    fn clique_status(&self, participants: BTreeSet<ParticipantId>) -> OnlineStatus;
}

impl CliqueStatus for NetworkGraph {
    fn clique_status(&self, participants: BTreeSet<ParticipantId>) -> OnlineStatus {
        for p1 in &participants {
            if self.offline_participants.contains(p1) {
                return OnlineStatus::Offline;
            }
            for p2 in participants.range((Excluded(p1), Unbounded)) {
                if self.offline_links.contains(&NetworkLink::new(*p1, *p2)) {
                    return OnlineStatus::Offline;
                }
            }
        }
        OnlineStatus::Online
    }
}

pub struct NetworkViewManagerHandle {
    pub update_sender: mpsc::Sender<NetworkViewUpdate>,
    pub connection_states_receiver: watch::Receiver<BTreeMap<Connection, ConnectionState>>,
    pub graph_receiver: watch::Receiver<NetworkGraph>,
    /// The [`ConnectedPeersInfo`] to broadcast: ourselves and every connected peer, each with the
    /// latest first-hand height, 0 when none is known.
    pub connected_peers_info_receiver: watch::Receiver<ConnectedPeersInfo>,
}

impl NetworkViewManagerHandle {
    pub fn new(
        me: ParticipantId,
        participants: &[ParticipantId],
        max_online_delay: u64,
        cancellation_token: CancellationToken,
    ) -> Self {
        let (update_sender, update_receiver) = mpsc::channel(participants.len());
        let connection_states: BTreeMap<Connection, ConnectionState> = participants
            .iter()
            .flat_map(|&from| {
                participants
                    .iter()
                    .filter(move |&&to| to != from)
                    .map(move |&to| (Connection { from, to }, ConnectionState::Unknown))
            })
            .collect();
        let (connection_states_sender, connection_states_receiver) =
            watch::channel(connection_states);
        let (graph_sender, graph_receiver) = watch::channel(NetworkGraph::default());
        let (connected_peers_info_sender, connected_peers_info_receiver) =
            watch::channel(ConnectedPeersInfo {
                peers: BTreeMap::from([(me, 0)]),
            });
        let manager = NetworkViewManager {
            me,
            max_online_delay,
            view: NetworkView::new(me, participants),
            connected_peers: BTreeSet::new(),
            connection_states_sender,
            graph_sender,
            connected_peers_info_sender,
        };
        tokio::spawn(run_network_view_manager(
            manager,
            update_receiver,
            cancellation_token,
        ));
        Self {
            update_sender,
            connection_states_receiver,
            graph_receiver,
            connected_peers_info_receiver,
        }
    }
}

async fn run_network_view_manager(
    mut manager: NetworkViewManager,
    mut update_receiver: mpsc::Receiver<NetworkViewUpdate>,
    cancellation_token: CancellationToken,
) {
    loop {
        let update = tokio::select! {
            () = cancellation_token.cancelled() => return,
            update = update_receiver.recv() => match update {
                Some(update) => update,
                None => return,
            },
        };
        manager.apply(update);
    }
}

struct NetworkViewManager {
    me: ParticipantId,
    max_online_delay: u64,
    view: NetworkView,
    connected_peers: BTreeSet<ParticipantId>,
    connection_states_sender: watch::Sender<BTreeMap<Connection, ConnectionState>>,
    graph_sender: watch::Sender<NetworkGraph>,
    connected_peers_info_sender: watch::Sender<ConnectedPeersInfo>,
}

impl NetworkViewManager {
    fn apply(&mut self, update: NetworkViewUpdate) {
        match update {
            NetworkViewUpdate::ConnectedPeersInfo(info) => {
                let reporter = info.from;
                let refreshed = self.view.update_with_info(info);
                self.publish_connection_states(&refreshed);
                self.graph_sender.send_if_modified(|graph| {
                    let links_changed = self.classify_links(&mut graph.offline_links, &refreshed);
                    let node_changed =
                        self.classify_node(&mut graph.offline_participants, reporter);
                    links_changed || node_changed
                });
                self.publish_listed_height(reporter);
            }
            NetworkViewUpdate::IndexerHeight {
                participant,
                height,
            } => {
                self.view.update_indexer_height(participant, height);
                self.graph_sender.send_if_modified(|graph| {
                    if participant == self.me {
                        self.classify_every_node(&mut graph.offline_participants)
                    } else {
                        self.classify_node(&mut graph.offline_participants, participant)
                    }
                });
                self.publish_listed_height(participant);
            }
            NetworkViewUpdate::ConnectedPeers(connected) => {
                let refreshed = self.view.update_connected_peers(&connected);
                self.connected_peers = connected;
                self.publish_connection_states(&refreshed);
                self.graph_sender.send_if_modified(|graph| {
                    self.classify_links(&mut graph.offline_links, &refreshed)
                });
                self.connected_peers_info_sender.send_modify(|info| {
                    info.peers.clear();
                    info.peers.insert(self.me, self.listed_height(self.me));
                    for &peer in &self.connected_peers {
                        info.peers.insert(peer, self.listed_height(peer));
                    }
                });
            }
        }
    }

    fn publish_connection_states(&self, refreshed: &[(Connection, ConnectionState)]) {
        self.connection_states_sender
            .send_modify(|states| states.extend(refreshed.iter().copied()));
    }

    fn classify_links(
        &self,
        offline_links: &mut BTreeSet<NetworkLink>,
        refreshed: &[(Connection, ConnectionState)],
    ) -> bool {
        let states = self.connection_states_sender.borrow();
        let mut changed = false;
        for &(connection, state) in refreshed {
            let inverse = states
                .get(&connection.inverse())
                .copied()
                .unwrap_or(ConnectionState::Unknown);
            let status = classify_link(state.worse(inverse), self.max_online_delay);
            changed |= set_status(
                offline_links,
                NetworkLink::new(connection.from, connection.to),
                status,
            );
        }
        changed
    }

    fn classify_node(
        &self,
        offline_participants: &mut BTreeSet<ParticipantId>,
        participant: ParticipantId,
    ) -> bool {
        let status = classify_node(
            self.view.indexer_height(self.me),
            self.view.indexer_height(participant),
        );
        set_status(offline_participants, participant, status)
    }

    fn classify_every_node(&self, offline_participants: &mut BTreeSet<ParticipantId>) -> bool {
        let own_height = self.view.indexer_height(self.me);
        let mut changed = false;
        for participant in self.view.participants() {
            let status = classify_node(own_height, self.view.indexer_height(participant));
            changed |= set_status(offline_participants, participant, status);
        }
        changed
    }

    fn publish_listed_height(&self, participant: ParticipantId) {
        if participant != self.me && !self.connected_peers.contains(&participant) {
            return;
        }
        let height = self.listed_height(participant);
        self.connected_peers_info_sender
            .send_if_modified(|info| info.peers.insert(participant, height) != Some(height));
    }

    fn listed_height(&self, participant: ParticipantId) -> u64 {
        self.view.indexer_height(participant).unwrap_or(0)
    }
}

fn classify_link(state: ConnectionState, max_online_delay: u64) -> OnlineStatus {
    match state {
        ConnectionState::Disconnected => OnlineStatus::Offline,
        ConnectionState::Delay(delay) if delay > max_online_delay => OnlineStatus::Offline,
        ConnectionState::Unknown | ConnectionState::Connected | ConnectionState::Delay(_) => {
            OnlineStatus::Online
        }
    }
}

/// The liveness rule of `MeshNetworkClient::all_alive_participant_ids`; a missing height never
/// vetoes.
fn classify_node(own_height: Option<u64>, peer_height: Option<u64>) -> OnlineStatus {
    match (own_height, peer_height) {
        (Some(own), Some(peer)) if own > peer.saturating_add(MAX_INDEXER_HEIGHT_DIFF) => {
            OnlineStatus::Offline
        }
        _ => OnlineStatus::Online,
    }
}

/// Returns whether the set changed.
fn set_status<T: Ord>(offline: &mut BTreeSet<T>, item: T, status: OnlineStatus) -> bool {
    match status {
        OnlineStatus::Online => offline.remove(&item),
        OnlineStatus::Offline => offline.insert(item),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{NetworkGraph, NetworkLink, NetworkViewManagerHandle, NetworkViewUpdate};
    use crate::network::view::network_view::{Connection, ConnectionState};
    use crate::primitives::{ConnectedPeersInfo, ParticipantId, PeerConnectedPeersInfo};
    use mpc_node_config::MAX_INDEXER_HEIGHT_DIFF;
    use std::collections::{BTreeMap, BTreeSet};
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const A: ParticipantId = ParticipantId::from_raw(1);
    const B: ParticipantId = ParticipantId::from_raw(2);
    const C: ParticipantId = ParticipantId::from_raw(3);
    const PARTICIPANTS: [ParticipantId; 4] = [ME, A, B, C];
    const H: u64 = 1_000;
    const MAX_ONLINE_DELAY: u64 = 5;

    fn handle() -> (NetworkViewManagerHandle, CancellationToken) {
        let cancellation_token = CancellationToken::new();
        let handle = NetworkViewManagerHandle::new(
            ME,
            &PARTICIPANTS,
            MAX_ONLINE_DELAY,
            cancellation_token.clone(),
        );
        (handle, cancellation_token)
    }

    fn info(from: ParticipantId, peers: &[(ParticipantId, u64)]) -> NetworkViewUpdate {
        NetworkViewUpdate::ConnectedPeersInfo(PeerConnectedPeersInfo {
            from,
            info: ConnectedPeersInfo {
                peers: peers.iter().copied().collect(),
            },
        })
    }

    fn indexer_height(participant: ParticipantId, height: u64) -> NetworkViewUpdate {
        NetworkViewUpdate::IndexerHeight {
            participant,
            height,
        }
    }

    fn connected_peers(peers: &[ParticipantId]) -> NetworkViewUpdate {
        NetworkViewUpdate::ConnectedPeers(peers.iter().copied().collect())
    }

    const fn connection(from: ParticipantId, to: ParticipantId) -> Connection {
        Connection { from, to }
    }

    /// Sends `update` and waits until the manager has applied it. A `ConnectedPeersInfo` or
    /// `ConnectedPeers` update always writes the connection states; an `IndexerHeight` update is
    /// waited for on the broadcast info, so its participant must be listed there with a different
    /// height.
    async fn apply(handle: &NetworkViewManagerHandle, update: NetworkViewUpdate) {
        let mut connection_states = handle.connection_states_receiver.clone();
        let mut connected_peers_info = handle.connected_peers_info_receiver.clone();
        connection_states.mark_unchanged();
        connected_peers_info.mark_unchanged();
        let is_indexer_height = matches!(update, NetworkViewUpdate::IndexerHeight { .. });
        handle
            .update_sender
            .send(update)
            .await
            .expect("manager must be running");
        let applied = if is_indexer_height {
            connected_peers_info.changed().await
        } else {
            connection_states.changed().await
        };
        applied.expect("manager must be running");
    }

    async fn changed<T>(receiver: &mut watch::Receiver<T>) {
        receiver.changed().await.expect("manager must be running");
    }

    #[tokio::test]
    async fn network_view_manager__should_start_with_every_node_and_link_online() {
        // Given
        let (handle, _cancellation_token) = handle();

        // When
        let graph = handle.graph_receiver.borrow().clone();

        // Then
        assert_eq!(graph, NetworkGraph::default());
    }

    #[tokio::test]
    async fn network_view_manager__should_prefill_every_connection_as_unknown() {
        // Given
        let (handle, _cancellation_token) = handle();

        // When
        let states = handle.connection_states_receiver.borrow().clone();

        // Then
        assert_eq!(states.len(), 12);
        assert!(
            states
                .values()
                .all(|&state| state == ConnectionState::Unknown)
        );
        assert!(
            PARTICIPANTS
                .iter()
                .all(|&participant| !states.contains_key(&connection(participant, participant)))
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_publish_the_connections_an_update_refreshes() {
        // Given
        let (handle, _cancellation_token) = handle();
        apply(&handle, info(A, &[(A, H), (B, H)])).await;

        // When
        apply(&handle, info(B, &[(B, H), (A, H - 4)])).await;

        // Then
        let states = handle.connection_states_receiver.borrow().clone();
        assert_eq!(states[&connection(A, B)], ConnectionState::Delay(4));
        assert_eq!(states[&connection(C, B)], ConnectionState::Disconnected);
        assert_eq!(states[&connection(B, A)], ConnectionState::Unknown);
    }

    #[tokio::test]
    async fn network_view_manager__should_mark_a_link_offline_when_its_worse_connection_exceeds_the_max_delay()
     {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, info(A, &[(A, H), (B, H)])).await;
        apply(&handle, info(B, &[(B, H), (A, H - 2)])).await;

        // When
        apply(&handle, info(A, &[(A, H), (B, H - 8)])).await;

        // Then
        changed(&mut graph).await;
        assert!(
            graph
                .borrow()
                .offline_links
                .contains(&NetworkLink::new(A, B))
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_keep_a_link_online_at_the_max_delay() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, info(A, &[(A, H), (ME, H), (B, H), (C, H)])).await;
        apply(&handle, info(B, &[(B, H), (ME, H), (A, H), (C, H)])).await;

        // When
        apply(
            &handle,
            info(A, &[(A, H), (ME, H), (B, H - MAX_ONLINE_DELAY), (C, H)]),
        )
        .await;

        // Then
        assert!(!graph.has_changed().expect("manager must be running"));
        assert!(graph.borrow().offline_links.is_empty());
        assert_eq!(
            handle.connection_states_receiver.borrow()[&connection(B, A)],
            ConnectionState::Delay(MAX_ONLINE_DELAY)
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_mark_a_link_offline_when_a_reporter_omits_its_peer() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, info(A, &[(A, H), (B, H)])).await;

        // When
        apply(&handle, info(B, &[(B, H)])).await;

        // Then
        changed(&mut graph).await;
        assert!(
            graph
                .borrow()
                .offline_links
                .contains(&NetworkLink::new(A, B))
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_mark_our_link_offline_for_a_peer_missing_from_connected_peers()
     {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();

        // When
        apply(&handle, connected_peers(&[A, C])).await;

        // Then
        changed(&mut graph).await;
        assert_eq!(
            graph.borrow().offline_links,
            BTreeSet::from([NetworkLink::new(ME, B)])
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_mark_a_node_offline_when_it_lags_more_than_max_indexer_height_diff_behind_us()
     {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, indexer_height(ME, H)).await;

        // When
        apply(&handle, info(A, &[(A, H - MAX_INDEXER_HEIGHT_DIFF - 1)])).await;

        // Then
        changed(&mut graph).await;
        assert!(graph.borrow().offline_participants.contains(&A));
    }

    #[tokio::test]
    async fn network_view_manager__should_keep_a_node_online_at_max_indexer_height_diff() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, indexer_height(ME, H)).await;

        // When
        apply(
            &handle,
            info(
                A,
                &[(A, H - MAX_INDEXER_HEIGHT_DIFF), (ME, H), (B, H), (C, H)],
            ),
        )
        .await;

        // Then
        assert!(!graph.has_changed().expect("manager must be running"));
        assert!(graph.borrow().offline_participants.is_empty());
    }

    #[tokio::test]
    async fn network_view_manager__should_reclassify_every_node_on_an_indexer_height_update() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, info(A, &[(A, H)])).await;
        apply(&handle, info(B, &[(B, H)])).await;

        // When
        apply(&handle, indexer_height(ME, H + MAX_INDEXER_HEIGHT_DIFF + 1)).await;

        // Then
        changed(&mut graph).await;
        assert_eq!(graph.borrow().offline_participants, BTreeSet::from([A, B]));
    }

    #[tokio::test]
    async fn network_view_manager__should_keep_a_node_without_a_height_online() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();

        // When
        apply(&handle, indexer_height(ME, H + MAX_INDEXER_HEIGHT_DIFF + 1)).await;

        // Then
        assert!(!graph.has_changed().expect("manager must be running"));
        assert!(graph.borrow().offline_participants.is_empty());
    }

    #[tokio::test]
    async fn network_view_manager__should_not_notify_graph_subscribers_when_only_a_delay_changes() {
        // Given
        let (handle, _cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();
        apply(&handle, info(A, &[(A, H), (B, H)])).await;
        apply(&handle, info(B, &[(B, H), (A, H)])).await;
        apply(&handle, info(A, &[(A, H), (B, H - 8)])).await;
        changed(&mut graph).await;
        assert!(
            graph
                .borrow()
                .offline_links
                .contains(&NetworkLink::new(A, B))
        );

        // When
        apply(&handle, info(A, &[(A, H), (B, H - 10)])).await;

        // Then
        assert!(!graph.has_changed().expect("manager must be running"));
        assert_eq!(
            handle.connection_states_receiver.borrow()[&connection(B, A)],
            ConnectionState::Delay(9)
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_publish_our_connected_peers_info_from_the_view() {
        // Given
        let (handle, _cancellation_token) = handle();
        apply(&handle, indexer_height(ME, H)).await;
        apply(&handle, info(A, &[(A, H - 1)])).await;

        // When
        apply(&handle, connected_peers(&[A, B])).await;

        // Then
        assert_eq!(
            handle.connected_peers_info_receiver.borrow().peers,
            BTreeMap::from([(ME, H), (A, H - 1), (B, 0)])
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_refresh_a_listed_height_on_an_indexer_height_update() {
        // Given
        let (handle, _cancellation_token) = handle();
        apply(&handle, connected_peers(&[A])).await;

        // When
        apply(&handle, indexer_height(A, H - 7)).await;

        // Then
        assert_eq!(
            handle.connected_peers_info_receiver.borrow().peers,
            BTreeMap::from([(ME, 0), (A, H - 7)])
        );
    }

    #[tokio::test]
    async fn network_view_manager__should_close_its_channels_on_cancellation() {
        // Given
        let (handle, cancellation_token) = handle();
        let mut graph = handle.graph_receiver.clone();

        // When
        cancellation_token.cancel();

        // Then
        assert!(graph.changed().await.is_err());
        assert!(handle.update_sender.is_closed());
    }
}
