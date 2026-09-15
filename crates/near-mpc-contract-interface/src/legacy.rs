//! Contract-update API of contract `3.15.0`, the version deployed on mainnet and testnet: an
//! update is stored on-chain via `propose_update` and applied by the threshold `vote_update(id)`.
//! Kept only so tests can upgrade a production contract to the current build; remove once
//! production runs the vote-then-submit API (`submit_update` / `vote_update(update_hash)`).

use crate::deposits::DepositOverflowError;
use crate::types::Config;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const PROPOSE_UPDATE: &str = "propose_update";

pub const PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES: u128 = 32_768;

pub fn propose_update_required_deposit_yoctonear(
    payload_bytes: u128,
    storage_byte_cost_yoctonear: u128,
) -> Result<u128, DepositOverflowError> {
    PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES
        .checked_add(payload_bytes)
        .and_then(|bytes| storage_byte_cost_yoctonear.checked_mul(bytes))
        .ok_or(DepositOverflowError)
}

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
    derive_more::From,
)]
pub struct UpdateId(pub u64);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<Config>,
}

impl ProposeUpdateArgs {
    pub fn payload_bytes(&self) -> Result<u128, PayloadBytesError> {
        let code_bytes = self.code.as_ref().map_or(0, |code| code.len());
        let config_bytes = self
            .config
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .map_or(0, |config| config.len());
        code_bytes
            .checked_add(config_bytes)
            .and_then(|payload_bytes| u128::try_from(payload_bytes).ok())
            .ok_or(PayloadBytesError::Overflow)
    }
}

/// Sizing a proposal's payload failed.
#[derive(Debug, thiserror::Error)]
pub enum PayloadBytesError {
    #[error("the config does not serialize to JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("the payload exceeds u128::MAX bytes")]
    Overflow,
}

#[cfg(feature = "call-args")]
#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteUpdateArgs {
    pub id: UpdateId,
}

#[cfg(feature = "client")]
mod client {
    use super::{PayloadBytesError, ProposeUpdateArgs, UpdateId, VoteUpdateArgs};
    use crate::client::{MAX_GAS, MpcContractHandle, MpcContractHandleError};
    use crate::deposits::{DepositOverflowError, STORAGE_BYTE_COST_YOCTONEAR};
    use crate::method_names::VOTE_UPDATE;
    use near_contract_transport::{CallContract, FunctionCallArgs, NearGas, NearToken};

    /// Gas for the threshold `vote_update(id)`, which deploys the proposed code.
    pub const VOTE_UPDATE_GAS: NearGas = NearGas::from_tgas(260);

    impl<C: CallContract> MpcContractHandle<C> {
        pub async fn propose_update(
            &self,
            args: ProposeUpdateArgs,
        ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
            let payload_bytes = args.payload_bytes()?;
            let deposit =
                NearToken::from_yoctonear(super::propose_update_required_deposit_yoctonear(
                    payload_bytes,
                    STORAGE_BYTE_COST_YOCTONEAR,
                )?);
            let args = borsh::to_vec(&args)?;
            self.call(FunctionCallArgs::new(
                super::PROPOSE_UPDATE,
                args,
                MAX_GAS,
                deposit,
            ))
            .await
        }

        pub async fn vote_update_by_id(
            &self,
            id: UpdateId,
        ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
            let args = serde_json::to_vec(&VoteUpdateArgs::new(id))?;
            self.call(FunctionCallArgs::no_deposit(
                VOTE_UPDATE,
                args,
                VOTE_UPDATE_GAS,
            ))
            .await
        }
    }

    impl<E> From<PayloadBytesError> for MpcContractHandleError<E> {
        fn from(value: PayloadBytesError) -> Self {
            match value {
                PayloadBytesError::Serialize(err) => MpcContractHandleError::Serialize(err),
                PayloadBytesError::Overflow => {
                    MpcContractHandleError::Deposit(DepositOverflowError)
                }
            }
        }
    }
}

#[cfg(feature = "client")]
pub use client::VOTE_UPDATE_GAS;
