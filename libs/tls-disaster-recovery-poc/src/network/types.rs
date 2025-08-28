use crate::network::messages::Messages;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Display, From};
use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(
    Clone,
    Debug,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Copy,
    Display,
    From,
)]
pub struct CommunicatorPeerId(u64);

#[derive(Hash, Clone, PartialEq, Eq, Debug)]
pub struct Peer {
    pub address: String,
    pub public_key: ed25519_dalek::VerifyingKey,
}

#[derive(Clone, Debug)]
pub struct CommPeers {
    id_by_key: HashMap<ed25519_dalek::VerifyingKey, CommunicatorPeerId>,
    peer_by_id: BTreeMap<CommunicatorPeerId, Peer>,
    next_id: CommunicatorPeerId,
}

impl CommPeers {
    pub fn new() -> Self {
        Self {
            id_by_key: HashMap::new(),
            peer_by_id: BTreeMap::new(),
            next_id: CommunicatorPeerId(0),
        }
    }

    /// Insert by unique public key and retruns its id.
    /// Returns an error if a peer with the same public key already exists.
    pub fn insert(&mut self, peer: Peer) -> anyhow::Result<CommunicatorPeerId> {
        if let Some(&id) = self.id_by_key.get(&peer.public_key) {
            anyhow::bail!("peer with public key already exists {}", id);
        }

        let id = self.next_id;
        self.next_id = CommunicatorPeerId(self.next_id.0.saturating_add(1));

        self.id_by_key.insert(peer.public_key.clone(), id);
        self.peer_by_id.insert(id, peer);
        Ok(id)
    }

    pub fn remove(&mut self, public_key: &ed25519_dalek::VerifyingKey) -> anyhow::Result<()> {
        let Some(id) = self.id_by_key.remove(public_key) else {
            anyhow::bail!("not a peer");
        };
        if self.peer_by_id.remove(&id).is_none() {
            anyhow::bail!("inconsistent map");
        };
        Ok(())
    }

    pub fn get(&self, peer_id: &CommunicatorPeerId) -> Option<&Peer> {
        self.peer_by_id.get(peer_id)
    }
    pub fn get_peer(&self, key: &ed25519_dalek::VerifyingKey) -> Option<Peer> {
        if let Some(id) = self.id_by_key.get(key) {
            self.get(id).cloned()
        } else {
            None
        }
    }
}

pub struct Connection {
    pub peer: Peer,
    cancel: CancellationToken,
    outgoing_messages: tokio::sync::mpsc::UnboundedSender<Messages>,
    incoming_messages: Mutex<tokio::sync::mpsc::UnboundedReceiver<Messages>>,
}

impl Connection {
    pub fn new(
        peer: Peer,
        cancel: CancellationToken,
        outgoing_messages: tokio::sync::mpsc::UnboundedSender<Messages>,
        incoming_messages: Mutex<tokio::sync::mpsc::UnboundedReceiver<Messages>>,
    ) -> Self {
        Self {
            peer,
            cancel,
            outgoing_messages,
            incoming_messages,
        }
    }
    pub fn send(&self, msg: Messages) -> anyhow::Result<()> {
        self.outgoing_messages.send(msg)?;
        Ok(())
    }
    pub async fn outgoing_closed(&self) {
        self.outgoing_messages.closed().await
    }
    pub async fn incoming_closed(&self) -> bool {
        self.incoming_messages.lock().await.is_closed()
    }
    pub async fn receive(&self) -> Option<Messages> {
        self.incoming_messages.lock().await.recv().await
    }
    pub async fn cancel(&self) {
        self.cancel.cancel();
        self.incoming_messages.lock().await.close();
    }
}

pub(crate) struct Connections {
    connections: HashMap<ed25519_dalek::VerifyingKey, Arc<Connection>>,
}

impl Connections {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Inserts the connection's cancellation token keyed by peer_id.
    /// Returns `false` if it was newly inserted, `true` if an existing entry was replaced.
    /// If replaced, the old connection is cancelled.
    pub async fn insert(&mut self, conn: Connection) -> bool {
        match self.connections.entry(conn.peer.public_key) {
            Entry::Vacant(v) => {
                v.insert(Arc::new(conn));
                false
            }
            Entry::Occupied(mut o) => {
                tracing::info!(
                    "replacing existing connection for peer {:?}",
                    conn.peer.public_key
                ); // todo: add targets
                // Cancel the previous connection for this peer.
                o.get().cancel().await;
                // todo: this locking mechanism sucks
                o.insert(Arc::new(conn));
                true
            }
        }
    }

    pub fn get(&self, key: &ed25519_dalek::VerifyingKey) -> Option<Arc<Connection>> {
        self.connections.get(key).cloned()
    }
}
