use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::UpperBoundedVec;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

use crate::types::MAX_EXTRACTORS_PER_REQUEST;

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SvmRpcRequest {
    pub tx_id: SvmTxId,
    pub finality: SvmFinality,
    pub extractors: UpperBoundedVec<SvmExtractor, MAX_EXTRACTORS_PER_REQUEST>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SvmFinality {
    Confirmed,
    Finalized,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum SvmExtractor {
    InnerInstruction {
        instruction_index: u64,
        inner_instruction_index: u64,
    } = 1,
    AccountState {
        pubkey: SvmAddress,
    } = 2,
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SvmAddress(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SvmInnerInstruction {
    pub program_id: SvmAddress,
    pub accounts: Vec<SvmAddress>,
    #[serde_as(as = "Hex")]
    pub data: Vec<u8>,
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SvmAccount {
    pub owner: SvmAddress,
    #[serde_as(as = "Hex")]
    pub data: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SvmExtractedValue {
    InnerInstruction(SvmInnerInstruction),
    AccountState(SvmAccount),
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SvmTxId(
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "Hex64Schema")
    )]
    #[serde_as(as = "Hex")]
    pub [u8; 64],
);

/// Hex-string schema for a 64-byte array, which schemars has no
/// [`JsonSchema`](schemars::JsonSchema) impl for.
#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
struct Hex64Schema;

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Hex64Schema {
    fn schema_name() -> String {
        "Hex64".to_string()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                pattern: Some(r"^(?:[0-9A-Fa-f]{2}){64}$".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}
