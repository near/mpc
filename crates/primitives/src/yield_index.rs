use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A 256-bit hash identifier, matching the layout of `near_sdk::CryptoHash`
/// (itself a bare `[u8; 32]` type alias). Defined here so `mpc-primitives`
/// does not have to pull in `near-sdk`.
pub type CryptoHash = [u8; 32];

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}
