use crypto_shared::{derive_epsilon, SerializableScalar};
use k256::Scalar;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, BorshStorageKey, CryptoHash, PublicKey};
use std::collections::{BTreeMap, HashSet};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    PendingRequests,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl SignatureRequest {
    pub fn new(payload_hash: Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = derive_epsilon(predecessor_id, path);
        let epsilon = SerializableScalar { scalar: epsilon };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        SignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct ParticipantInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

impl From<CandidateInfo> for ParticipantInfo {
    fn from(candidate_info: CandidateInfo) -> Self {
        ParticipantInfo {
            account_id: candidate_info.account_id,
            url: candidate_info.url,
            cipher_pk: candidate_info.cipher_pk,
            sign_pk: candidate_info.sign_pk,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
}

impl Default for Participants {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Candidates> for Participants {
    fn from(candidates: Candidates) -> Self {
        let mut participants = Participants::new();
        for (account_id, candidate_info) in candidates.iter() {
            participants.insert(account_id.clone(), candidate_info.clone().into());
        }
        participants
    }
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            participants: BTreeMap::new(),
        }
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, participant_info: ParticipantInfo) {
        self.participants.insert(account_id, participant_info);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.participants.remove(account_id);
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &ParticipantInfo)> {
        self.participants.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.participants.keys()
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl Default for Candidates {
    fn default() -> Self {
        Self::new()
    }
}

impl Candidates {
    pub fn new() -> Self {
        Candidates {
            candidates: BTreeMap::new(),
        }
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.candidates.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, candidate: CandidateInfo) {
        self.candidates.insert(account_id, candidate);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.candidates.remove(account_id);
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(account_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo)> {
        self.candidates.iter()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Default for Votes {
    fn default() -> Self {
        Self::new()
    }
}

impl Votes {
    pub fn new() -> Self {
        Votes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, account_id: AccountId) -> &mut HashSet<AccountId> {
        self.votes.entry(account_id).or_default()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
}

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug)]
pub struct SignResult {
    pub big_r: String,
    pub s: String,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignaturePromiseError {
    Failed,
}
