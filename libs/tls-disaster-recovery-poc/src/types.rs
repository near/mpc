use std::collections::{BTreeMap, HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Display, From};

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
    /// Unique identity: VerifyingKey -> assigned id
    id_by_key: HashMap<ed25519_dalek::VerifyingKey, CommunicatorPeerId>,
    /// Map: id -> Peer
    peer_by_id: BTreeMap<CommunicatorPeerId, Peer>,
    /// Next id to assign
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

    pub fn ids(&self) -> Vec<CommunicatorPeerId> {
        self.peer_by_id.keys().cloned().collect()
    }
    pub fn get(&self, peer_id: &CommunicatorPeerId) -> Option<&Peer> {
        self.peer_by_id.get(peer_id)
    }
    pub fn is_allowed(&self, key: &ed25519_dalek::VerifyingKey) -> Option<CommunicatorPeerId> {
        self.id_by_key.get(key).copied()
    }
}

// todo: tests
