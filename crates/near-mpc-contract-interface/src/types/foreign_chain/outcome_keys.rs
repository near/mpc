use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::types::{AccountId, Ed25519PublicKey};

/// The outcome key each participant account registered. A node signs its node outcomes for
/// V2 foreign transaction requests with this key, and other nodes check them against it.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct OutcomeKeys(BTreeMap<AccountId, Ed25519PublicKey>);
