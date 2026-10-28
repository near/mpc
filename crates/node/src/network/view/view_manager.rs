use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

use tokio::sync::{mpsc, watch};

use crate::network::view::network_view::NetworkView;
use crate::primitives::{ParticipantId, PeerConnectedPeersInfo};

pub struct NetworkViewManager {
    pub graph_receiver: watch::Receiver<NetworkGraph>,
    pub heights_sender: mpsc::Sender<PeerConnectedPeersInfo>, // add a task:
}

// task for network view manager:
// 1. monitor a receive channel (mpsc). Receive online status from peers, then proccess them and
//    pass them on to the inner network_view
// 2. inform any subscribers about any status changes

impl NetworkViewManager {
    fn subscribe(&self) -> tokio::sync::watch::Receiver<NetworkGraph> {
        self.receiver.clone()
    }
    fn new(participants: &[ParticipantId]) -> Self {
        let (graph_sender, graph_receiver) = watch::channel(NetworkGraph::default());
        let (data_sender, data_receiver) = mpsc::channel(participants.len());
        spawn_network_manager(graph_sender, data_receiver, participants);
        Self {
            graph_receiver,
            heights_sender: data_sender,
        }
    }
}

async fn spawn_network_manager(
    graph_sender: watch::Sender<NetworkGraph>,
    mut data_receiver: mpsc::Receiver<PeerConnectedPeersInfo>,
    participants: &[ParticipantId],
) {
    let mut network_view = NetworkView::new(participants);

    // note: task is dropped if all senders are dropped
    // mayde we sould add a cancellation token here.
    loop {
        let Some(received) = data_receiver.recv().await else {
            tracing::info!("closed");
            return;
        };
        network_view.update_with_info(received);
    }
    // this is not yet spawned, but we will et there
}

enum NodeStatus {
    Online,
    Offline,
}

/// an unordered pair of participant ids. Always uset he constructor for this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct NetworkLink(ParticipantId, ParticipantId);

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

enum LinkStatus {
    Online,
    Offline,
}

#[derive(Default)]
struct NetworkGraph {
    pub offline_participants: BTreeSet<ParticipantId>,
    pub offline_links: BTreeSet<NetworkLink>,
}

trait CliqueStatus {
    fn clique_status(&self, participants: BTreeSet<ParticipantId>) -> LinkStatus;
}

impl CliqueStatus for NetworkGraph {
    fn clique_status(&self, participants: BTreeSet<ParticipantId>) -> LinkStatus {
        for p1 in &participants {
            if self.offline_participants.contains(p1) {
                return LinkStatus::Offline;
            }
            for p2 in participants.range((Excluded(p1), Unbounded)) {
                if self.offline_links.contains(&NetworkLink::new(*p1, *p2)) {
                    return LinkStatus::Offline;
                }
            }
        }
        LinkStatus::Online
    }
}
