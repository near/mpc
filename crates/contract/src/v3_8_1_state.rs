//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{near, store::LookupMap};

use crate::{
    errors::{Error, InvalidParameters},
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::DomainId,
        signature::{Tweak, YieldIndex},
    },
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: OldStaleData,
    metrics: dtos::Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV3),
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {
                pending_signature_requests_pre_upgrade: value.pending_signature_requests,
            },
            metrics: value.metrics,
        }
    }
}

/// Old `StaleData` was an empty struct — must match the on-chain borsh layout exactly.
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct OldStaleData {}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct SignatureRequest {
    pub tweak: Tweak,
    pub payload: Payload,
    pub domain_id: DomainId,
}

/// A signature payload; the right payload must be passed in for the curve.
/// The json encoding for this payload converts the bytes to hex string.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub enum Payload {
    Ecdsa(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "[u8; 32]"),
            borsh(schema(with_funcs(
                declaration = "<[u8; 32] as ::borsh::BorshSchema>::declaration",
                definitions = "<[u8; 32] as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 32>,
    ),
    Eddsa(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>"),
            borsh(schema(with_funcs(
                declaration = "<Vec<u8> as ::borsh::BorshSchema>::declaration",
                definitions = "<Vec<u8> as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 1232>,
    ),
}

impl<const MIN_LEN: usize, const MAX_LEN: usize> Bytes<MIN_LEN, MAX_LEN> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < MIN_LEN || bytes.len() > MAX_LEN {
            return Err(InvalidParameters::MalformedPayload {
                reason: format!(
                    "expected length between {} and {}, got {}",
                    MIN_LEN,
                    MAX_LEN,
                    bytes.len()
                ),
            }
            .into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A byte array with a statically encoded minimum and maximum length.
/// The `new` function as well as json deserialization checks that the length is within bounds.
/// The borsh deserialization does not perform such checks, as the borsh serialization is only
/// used for internal contract storage.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh])]
pub struct Bytes<const MIN_LEN: usize, const MAX_LEN: usize>(Vec<u8>);

impl<const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Serialize
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        near_sdk::serde::Serialize::serialize(&hex::encode(&self.0), serializer)
    }
}

impl<'de, const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Deserialize<'de>
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: near_sdk::serde::Deserializer<'de>,
    {
        let s = <String as near_sdk::serde::Deserialize>::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(near_sdk::serde::de::Error::custom)?;
        Self::new(bytes).map_err(near_sdk::serde::de::Error::custom)
    }
}

impl From<&crate::primitives::signature::SignatureRequest> for SignatureRequest {
    fn from(request: &crate::primitives::signature::SignatureRequest) -> Self {
        let payload = match &request.payload {
            crate::primitives::signature::Payload::Ecdsa(bytes) => {
                Payload::Ecdsa(Bytes(bytes.as_slice().to_vec()))
            }
            crate::primitives::signature::Payload::Eddsa(bytes) => {
                Payload::Eddsa(Bytes(bytes.as_slice().to_vec()))
            }
        };
        SignatureRequest {
            tweak: request.tweak.clone(),
            payload,
            domain_id: request.domain_id,
        }
    }
}
