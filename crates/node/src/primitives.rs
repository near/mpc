use crate::providers::eddsa::EddsaTaskId;
use crate::providers::robust_ecdsa::RobustEcdsaTaskId;
use crate::providers::EcdsaTaskId;
use crate::providers::{ckd::CKDTaskId, verify_foreign_tx::VerifyForeignTxTaskId};
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::curve25519_dalek::EdwardsPoint;
use near_mpc_contract_interface::types as dtos;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use threshold_signatures::participants::Participant;

/// A unique ID representing a resource (e.g., a triple/presignature/signature, or a channel).
/// The ID shall be globally unique across all participants and across time.
///
/// The ID does not need to be globally unique across different *types* of assets,
/// as in, it is OK for a triple to have the same unique ID as a presignature.
///
/// The uniqueness of the unique ID is based on some assumptions:
///  - Participants follow the correct unique ID generation algorithm;
///    specifically, they each only pick unique IDs they are allowed to pick from.
///  - At least one second passes during a restart of the binary.
///
/// The unique ID contains three parts: the participant ID, the timestamp, and a
/// counter. The counter is used to distinguish between multiple assets generated
/// by the same participant during the same second.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniqueId(u128);

impl UniqueId {
    /// Only for testing. Use `generate` or `pick_new_after` instead.
    pub fn new(participant_id: ParticipantId, timestamp: u64, counter: u32) -> Self {
        let id =
            ((participant_id.raw() as u128) << 96) | ((timestamp as u128) << 32) | counter as u128;
        Self(id)
    }

    /// Generates a unique ID using the current wall time.
    pub fn generate(participant_id: ParticipantId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::new(participant_id, now, 0)
    }

    pub fn participant_id(&self) -> ParticipantId {
        ParticipantId::from_raw((self.0 >> 96) as u32)
    }

    pub fn timestamp(&self) -> u64 {
        ((self.0 >> 32) & ((1u128 << 64) - 1)) as u64
    }

    pub fn counter(&self) -> u32 {
        (self.0 & ((1u128 << 32) - 1)) as u32
    }

    /// Returns the key prefix for the given participant ID. It can be used to
    /// perform a range query in the database for all keys for this participant.
    pub fn prefix_for_participant_id(participant_id: ParticipantId) -> Vec<u8> {
        participant_id.raw().to_be_bytes().to_vec()
    }

    /// Pick a new unique ID based on the current time, but ensuring that it is
    /// after the current unique ID. All unique IDs should be picked this way,
    /// except the very first one, which should be generated with `generate`.
    pub fn pick_new_after(&self) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.timestamp() {
            Self::new(self.participant_id(), now, 0)
        } else {
            Self::new(self.participant_id(), self.timestamp(), self.counter() + 1)
        }
    }

    /// Validates that this unique ID belongs to the given participant.
    /// Returns an error if the embedded participant ID does not match.
    pub fn validate_owned_by(&self, expected: ParticipantId) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.participant_id() == expected,
            "UniqueId {:?} belongs to participant {}, expected {}",
            self,
            self.participant_id(),
            expected
        );
        Ok(())
    }

    /// Add the given delta to the counter, returning a new unique ID.
    /// This is useful for generating multiple unique IDs in a row, for batched
    /// generation of multiple assets at once.
    pub fn add_to_counter(&self, delta: u32) -> anyhow::Result<Self> {
        let new_counter = self
            .counter()
            .checked_add(delta)
            .context("Counter overflow")?;
        Ok(Self::new(
            self.participant_id(),
            self.timestamp(),
            new_counter,
        ))
    }
}

impl Debug for UniqueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UniqueId")
            .field(&self.participant_id())
            .field(&self.timestamp())
            .field(&self.counter())
            .finish()
    }
}

impl BorshSerialize for UniqueId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We must serialize in big-endian order to ensure that the
        // lexicalgraphical order of the keys is the same as the numerical
        // order.
        writer.write_all(&self.0.to_be_bytes())
    }
}

impl BorshDeserialize for UniqueId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)?;
        Ok(Self(u128::from_be_bytes(bytes)))
    }
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ParticipantId(u32);

impl From<Participant> for ParticipantId {
    fn from(participant: Participant) -> Self {
        ParticipantId(participant.into())
    }
}
impl From<mpc_contract::primitives::participants::ParticipantId> for ParticipantId {
    fn from(participant: mpc_contract::primitives::participants::ParticipantId) -> Self {
        ParticipantId(participant.get())
    }
}
impl From<ParticipantId> for Participant {
    fn from(participant_id: ParticipantId) -> Self {
        Participant::from(participant_id.0)
    }
}

impl ParticipantId {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(raw: u32) -> Self {
        ParticipantId(raw)
    }
}

impl From<near_mpc_contract_interface::types::AuthenticatedParticipantId> for ParticipantId {
    fn from(p: near_mpc_contract_interface::types::AuthenticatedParticipantId) -> Self {
        ParticipantId(p.0 .0)
    }
}

impl From<near_mpc_contract_interface::types::ParticipantId> for ParticipantId {
    fn from(p: near_mpc_contract_interface::types::ParticipantId) -> Self {
        ParticipantId(p.0)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// todo: move some of these to a new file

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyset {
    pub epoch_id: EpochId,
    pub domains: Vec<KeyForDomain>,
}

impl Keyset {
    pub fn new(epoch_id: EpochId, domains: Vec<KeyForDomain>) -> Self {
        Keyset { epoch_id, domains }
    }

    pub fn get_domain_ids(&self) -> Vec<DomainId> {
        self.domains.iter().map(|d| d.domain_id).collect()
    }

    pub fn public_key(&self, domain_id: DomainId) -> anyhow::Result<PublicKeyExtended> {
        self.domains
            .iter()
            .find(|k| k.domain_id == domain_id)
            .map(|k| k.key.clone())
            .ok_or_else(|| anyhow::anyhow!("No key for domain {:?}", domain_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub curve: Curve,
    pub purpose: DomainPurpose,
}

/// The purpose that a domain serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum DomainPurpose {
    /// Domain is used by `sign()`.
    Sign,
    /// Domain is used by `verify_foreign_transaction()`.
    ForeignTx,
    /// Domain is used by `request_app_private_key()` (Confidential Key Derivation).
    CKD,
}
impl From<dtos::DomainPurpose> for DomainPurpose {
    fn from(value: dtos::DomainPurpose) -> Self {
        match value {
            dtos::DomainPurpose::CKD => Self::CKD,
            dtos::DomainPurpose::Sign => Self::Sign,
            dtos::DomainPurpose::ForeignTx => Self::ForeignTx,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    Edwards25519,
    Bls12381,
    V2Secp256k1, // Robust ECDSA
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyForDomain {
    /// Identifies the domain this key is intended for.
    pub domain_id: DomainId,
    /// Identifies the public key. Although technically redundant given that we have the AttemptId,
    /// we keep it here in the contract so that it can be verified against and queried.
    pub key: PublicKeyExtended,
    /// The attempt ID that generated (initially or as a result of resharing) this distributed key.
    /// Nodes may have made multiple attempts to generate the distributed key, and this uniquely
    /// identifies which one should ultimately be used.
    pub attempt: AttemptId,
}

use elliptic_curve::group::GroupEncoding;

impl TryFrom<dtos::PublicKeyExtended> for PublicKeyExtended {
    type Error = anyhow::Error;
    fn try_from(pk: dtos::PublicKeyExtended) -> Result<Self, Self::Error> {
        match pk {
            dtos::PublicKeyExtended::Secp256k1 { near_public_key } => {
                let pk: near_sdk::PublicKey = near_public_key
                    .parse()
                    .context("PublicKeyExtendedConversionError::PublicKeyLengthMalformed")?;
                Ok(Self::Secp256k1 {
                    near_public_key: pk,
                })
            }
            dtos::PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                edwards_point,
            } => {
                let pk: near_sdk::PublicKey = near_public_key_compressed
                    .parse()
                    .context("PublicKeyExtendedConversionError::PublicKeyLengthMalformed")?;
                let edwards_point = EdwardsPoint::from_bytes(&edwards_point)
                    .map(Into::into)
                    .into_option()
                    .ok_or(anyhow::anyhow!(
                        "PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint",
                    ))?;
                Ok(Self::Ed25519 {
                    near_public_key_compressed: pk,
                    edwards_point,
                })
            }
            dtos::PublicKeyExtended::Bls12381 { public_key } => Ok(Self::Bls12381 { public_key }),
        }
    }
}

impl TryFrom<dtos::PublicKey> for PublicKeyExtended {
    type Error = anyhow::Error;
    fn try_from(public_key: dtos::PublicKey) -> Result<Self, Self::Error> {
        match public_key {
            dtos::PublicKey::Ed25519(inner_public_key) => {
                let near_public_key: near_sdk::PublicKey = inner_public_key.into();
                let public_key_bytes: &[u8; 32] = near_public_key
                    .as_bytes()
                    .get(1..)
                    .map(TryInto::try_into)
                    .ok_or_else(|| anyhow::anyhow!("PublicKey length malformed"))?
                    .map_err(|_| anyhow::anyhow!("PublicKey length malformed"))?;

                let edwards_point: SerializableEdwardsPoint =
                    EdwardsPoint::from_bytes(public_key_bytes)
                        .map(SerializableEdwardsPoint::from)
                        .into_option()
                        .ok_or_else(|| anyhow::anyhow!("Failed decompressing to EdwardsPoint"))?;

                Ok(Self::Ed25519 {
                    near_public_key_compressed: near_public_key,
                    edwards_point,
                })
            }
            dtos::PublicKey::Secp256k1(inner_public_key) => {
                let near_public_key: near_sdk::PublicKey = inner_public_key.into();
                Ok(Self::Secp256k1 { near_public_key })
            }
            dtos::PublicKey::Bls12381(inner_public_key) => Ok(Self::Bls12381 {
                public_key: dtos::PublicKey::from(inner_public_key),
            }),
        }
    }
}

impl From<dtos::EpochId> for EpochId {
    fn from(id: dtos::EpochId) -> Self {
        EpochId(id.0)
    }
}

impl From<dtos::AttemptId> for AttemptId {
    fn from(id: dtos::AttemptId) -> Self {
        AttemptId(id.0)
    }
}

impl From<dtos::Curve> for Curve {
    fn from(curve: dtos::Curve) -> Self {
        match curve {
            dtos::Curve::Secp256k1 => Curve::Secp256k1,
            dtos::Curve::Edwards25519 => Curve::Edwards25519,
            dtos::Curve::Bls12381 => Curve::Bls12381,
            dtos::Curve::V2Secp256k1 => Curve::V2Secp256k1,
        }
    }
}

impl From<dtos::DomainConfig> for DomainConfig {
    fn from(config: dtos::DomainConfig) -> Self {
        DomainConfig {
            id: DomainId(config.id.0),
            curve: config.curve.into(),
            purpose: config.purpose.into(),
        }
    }
}

impl From<dtos::KeyEventId> for KeyEventId {
    fn from(id: dtos::KeyEventId) -> Self {
        KeyEventId {
            epoch_id: id.epoch_id.into(),
            domain_id: id.domain_id.into(),
            attempt_id: id.attempt_id.into(),
        }
    }
}

impl TryFrom<dtos::KeyForDomain> for KeyForDomain {
    type Error = anyhow::Error;
    fn try_from(kfd: dtos::KeyForDomain) -> Result<Self, Self::Error> {
        Ok(KeyForDomain {
            domain_id: DomainId(kfd.domain_id.0),
            key: kfd
                .key
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert PublicKeyExtended: {e:?}"))?,
            attempt: kfd.attempt.into(),
        })
    }
}

impl TryFrom<dtos::Keyset> for Keyset {
    type Error = anyhow::Error;
    fn try_from(keyset: dtos::Keyset) -> Result<Self, Self::Error> {
        let domains: Result<Vec<KeyForDomain>, _> =
            keyset.domains.into_iter().map(TryFrom::try_from).collect();
        // we skip validation
        Ok(Keyset {
            epoch_id: keyset.epoch_id.into(),
            domains: domains?,
        })
    }
}

impl From<PublicKeyExtended> for dtos::PublicKeyExtended {
    fn from(pk: PublicKeyExtended) -> Self {
        match pk {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                dtos::PublicKeyExtended::Secp256k1 {
                    near_public_key: near_public_key.to_string(),
                }
            }
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                edwards_point,
            } => dtos::PublicKeyExtended::Ed25519 {
                near_public_key_compressed: near_public_key_compressed.to_string(),
                edwards_point: edwards_point.compress().to_bytes(),
            },
            PublicKeyExtended::Bls12381 { public_key } => {
                dtos::PublicKeyExtended::Bls12381 { public_key }
            }
        }
    }
}

impl From<KeyForDomain> for dtos::KeyForDomain {
    fn from(kfd: KeyForDomain) -> Self {
        dtos::KeyForDomain {
            domain_id: kfd.domain_id.into(),
            key: kfd.key.into(),
            attempt: kfd.attempt.into(),
        }
    }
}

impl From<Keyset> for dtos::Keyset {
    fn from(keyset: Keyset) -> Self {
        dtos::Keyset {
            epoch_id: keyset.epoch_id.into(),
            domains: keyset.domains.into_iter().map(Into::into).collect(),
        }
    }
}

/// Conversion to the contract-interface PublicKey type
impl From<PublicKeyExtended> for dtos::PublicKey {
    fn from(pk: PublicKeyExtended) -> Self {
        match pk {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                let key_data = near_public_key.as_bytes();
                // near_sdk PublicKey has a 1-byte prefix (curve type) followed by the key data
                let pk_bytes: [u8; 64] = key_data[1..]
                    .try_into()
                    .expect("Secp256k1 public key should be 64 bytes");
                dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey(pk_bytes))
            }
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => {
                let key_data = near_public_key_compressed.as_bytes();
                let pk_bytes: [u8; 32] = key_data[1..]
                    .try_into()
                    .expect("Ed25519 public key should be 32 bytes");
                dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey(pk_bytes))
            }
            PublicKeyExtended::Bls12381 { public_key } => public_key,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum PublicKeyExtended {
    Secp256k1 {
        near_public_key: near_sdk::PublicKey,
    },
    // Invariant: `edwards_point` is always the decompressed representation of `near_public_key_compressed`.
    Ed25519 {
        /// Serialized compressed Edwards-y point.
        near_public_key_compressed: near_sdk::PublicKey,
        /// Decompressed Edwards point used for curve arithmetic operations.
        edwards_point: SerializableEdwardsPoint,
    },
    Bls12381 {
        public_key: dtos::PublicKey,
    },
}

#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    Clone,
    Copy,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Deref,
)]
pub struct SerializableEdwardsPoint(
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "[u8; 32]"),
        borsh(schema(with_funcs(
            declaration = "<[u8; 32] as ::borsh::BorshSchema>::declaration",
            definitions = "<[u8; 32] as ::borsh::BorshSchema>::add_definitions_recursively"
        ),))
    )]
    EdwardsPoint,
);

/// A batched list of multiple cait-sith protocol messages.
pub type BatchedMessages = Vec<Vec<u8>>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
pub struct ChannelId(pub UniqueId);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcMessage {
    pub channel_id: ChannelId,
    pub kind: MpcMessageKind,
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MpcMessageKind {
    Start(MpcStartMessage),
    Computation(Vec<Vec<u8>>),
    Abort(String),
    Success,
}

/// Redacts the raw bytes in Computation messages.
/// These bytes contain serialized protocol round data (commitments, encrypted shares, proofs)
/// which must not be leaked to logs.
impl Debug for MpcMessageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcMessageKind::Start(msg) => f.debug_tuple("Start").field(msg).finish(),
            MpcMessageKind::Computation(chunks) => f
                .debug_tuple("Computation")
                .field(&format_args!(
                    "[{} chunks, {} bytes]",
                    chunks.len(),
                    chunks.iter().map(|c| c.len()).sum::<usize>()
                ))
                .finish(),
            MpcMessageKind::Abort(err) => f.debug_tuple("Abort").field(err).finish(),
            MpcMessageKind::Success => write!(f, "Success"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcStartMessage {
    pub task_id: MpcTaskId,
    pub participants: Vec<ParticipantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    EcdsaTaskId(EcdsaTaskId),
    EddsaTaskId(EddsaTaskId),
    CKDTaskId(CKDTaskId),
    RobustEcdsaTaskId(RobustEcdsaTaskId),
    VerifyForeignTxTaskId(VerifyForeignTxTaskId),
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IndexerHeightMessage {
    pub height: u64,
}

pub struct PeerIndexerHeightMessage {
    pub from: ParticipantId,
    pub message: IndexerHeightMessage,
}

pub enum PeerMessage {
    Mpc(MpcPeerMessage),
    IndexerHeight(PeerIndexerHeightMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
    pub build: String,
    pub commit: String,
    #[serde(default)]
    pub rustc_version: String,
}

// below types are copy-paste from the contract-interface crate. Note that we don't want to depend
// on those, as we don't want contract-interface changes to have an impact on any rocksdb changes
// we have in the node

/// Identifier for a key event (generation or resharing attempt).
/// This is duplicated from contract_interface, but for good reason. We don't want a change to the
/// interface crate requiring database changes on the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct KeyEventId {
    pub epoch_id: EpochId,
    pub domain_id: DomainId,
    pub attempt_id: AttemptId,
}

impl KeyEventId {
    pub fn new(epoch_id: EpochId, domain_id: DomainId, attempt_id: AttemptId) -> Self {
        KeyEventId {
            epoch_id,
            domain_id,
            attempt_id,
        }
    }
}

impl From<KeyEventId> for near_mpc_contract_interface::types::KeyEventId {
    fn from(val: KeyEventId) -> Self {
        near_mpc_contract_interface::types::KeyEventId {
            epoch_id: val.epoch_id.into(),
            domain_id: val.domain_id.into(),
            attempt_id: val.attempt_id.into(),
        }
    }
}

/// An EpochId uniquely identifies a ThresholdParameters (but not vice-versa).
/// Every time we change the ThresholdParameters (participants and threshold),
/// we increment EpochId.
/// Locally on each node, each keyshare is uniquely identified by the tuple
/// (EpochId, DomainId, AttemptId).
#[derive(
    // todo: search all instances of .0 and replace with *
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    derive_more::Deref,
)]
pub struct EpochId(pub(crate) u64);

impl EpochId {
    pub fn new(epoch_id: u64) -> Self {
        EpochId(epoch_id)
    }
}

impl Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<EpochId> for near_mpc_contract_interface::types::EpochId {
    fn from(val: EpochId) -> Self {
        near_mpc_contract_interface::types::EpochId(*val)
    }
}

/// Attempt identifier within a key event.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Deref,
)]
pub struct AttemptId(pub u64);

impl AttemptId {
    pub fn legacy_attempt_id() -> Self {
        AttemptId(0)
    }
}

impl Display for AttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AttemptId> for near_mpc_contract_interface::types::AttemptId {
    fn from(val: AttemptId) -> Self {
        near_mpc_contract_interface::types::AttemptId(*val)
    }
}
/// Threshold value for distributed key operations.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Deref,
)]
pub struct DomainId(pub u64);

impl DomainId {
    pub fn legacy_ecdsa_id() -> Self {
        DomainId(0)
    }
}

impl Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<dtos::DomainId> for DomainId {
    fn from(id: dtos::DomainId) -> Self {
        DomainId(id.0)
    }
}

impl From<DomainId> for near_mpc_contract_interface::types::DomainId {
    fn from(val: DomainId) -> Self {
        near_mpc_contract_interface::types::DomainId(*val)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_owned_by_accepts_matching_participant() {
        // given
        let participant = ParticipantId::from_raw(5);
        let id = UniqueId::new(participant, 1000, 0);
        let id_from_batch = id.add_to_counter(42).unwrap();

        // when/then
        id.validate_owned_by(participant).unwrap();
        id_from_batch.validate_owned_by(participant).unwrap();
    }

    #[test]
    fn test_validate_owned_by_rejects_mismatched_participant() {
        // given
        let owner = ParticipantId::from_raw(5);
        let other = ParticipantId::from_raw(99);
        let id = UniqueId::new(owner, 1000, 0);

        // when
        let err = id
            .validate_owned_by(other)
            .expect_err("Should reject mismatched participant");

        // then
        assert!(
            err.to_string().contains("expected 99"),
            "Unexpected error message: {}",
            err
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn mpc_message_kind_debug__should_redact_computation_payload() {
        // given
        let secret_data = b"SECRET_SHARE_DATA_THAT_MUST_NOT_LEAK".to_vec();
        let kind = MpcMessageKind::Computation(vec![secret_data]);

        // when
        let debug_output = format!("{:?}", kind);

        // then
        assert!(
            !debug_output.contains("SECRET_SHARE_DATA"),
            "Debug output must not contain raw computation bytes, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("Computation"),
            "Debug output should identify the message kind, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("1 chunks"),
            "Debug output should show chunk count, got: {}",
            debug_output
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn mpc_message_kind_debug__should_show_chunk_count_and_total_bytes() {
        // given
        let kind = MpcMessageKind::Computation(vec![vec![0u8; 100], vec![0u8; 200], vec![0u8; 50]]);

        // when
        let debug_output = format!("{:?}", kind);

        // then
        assert!(
            debug_output.contains("3 chunks"),
            "Debug output should show 3 chunks, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("350 bytes"),
            "Debug output should show 350 total bytes, got: {}",
            debug_output
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn mpc_message_kind_debug__should_show_non_sensitive_variants_normally() {
        // given
        let start = MpcMessageKind::Start(MpcStartMessage {
            task_id: MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples {
                start: UniqueId::new(ParticipantId::from_raw(0), 42, 0),
                count: 1,
            }),
            participants: vec![ParticipantId::from_raw(0)],
        });
        let abort = MpcMessageKind::Abort("some error".into());
        let success = MpcMessageKind::Success;

        // when
        let start_debug = format!("{:?}", start);
        let abort_debug = format!("{:?}", abort);
        let success_debug = format!("{:?}", success);

        // then
        assert!(start_debug.contains("Start"), "got: {}", start_debug);
        assert!(
            abort_debug.contains("some error"),
            "Abort debug should show the error string, got: {}",
            abort_debug
        );
        assert_eq!(success_debug, "Success");
    }

    #[test]
    #[expect(non_snake_case)]
    fn mpc_peer_message_debug__should_redact_computation_payload() {
        // given
        let secret_data = b"PRIVATE_KEY_SHARE_MATERIAL".to_vec();
        let message = MpcPeerMessage {
            from: ParticipantId::from_raw(1),
            message: MpcMessage {
                channel_id: ChannelId(UniqueId::new(ParticipantId::from_raw(0), 99, 0)),
                kind: MpcMessageKind::Computation(vec![secret_data]),
            },
        };

        // when
        let debug_output = format!("{:?}", message);

        // then
        assert!(
            !debug_output.contains("PRIVATE_KEY_SHARE"),
            "MpcPeerMessage debug must not leak computation bytes, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("1 chunks"),
            "Should show chunk metadata, got: {}",
            debug_output
        );
    }
}
