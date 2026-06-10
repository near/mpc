use near_mpc_contract_interface::types::{Hash256, TonCellBody, TonCellRefs};
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Identifies a TON transaction to inspect: the (basechain) account that
/// produced it plus the transaction hash. The workchain is carried explicitly
/// so non-basechain requests can be rejected before any RPC round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TonTransactionId {
    pub workchain: TonWorkchain,
    pub account: [u8; 32],
    pub tx_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonFinality {
    MasterchainIncluded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonExtractor {
    Log { message_index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonAddress {
    pub workchain: TonWorkchain,
    pub hash: Hash256,
}

/// TON workchain id, modelled as the `int8` the TON `addr_std` format and the
/// contract DTO use, so the two enums encode the same value identically (e.g. a
/// future masterchain `= -1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(i8)]
pub enum TonWorkchain {
    Basechain = 0,
}

impl TonWorkchain {
    pub(crate) fn id(self) -> i32 {
        i32::from(i8::from(self))
    }
}

/// A TON outbound log message extracted by the inspector. The cell payload
/// reuses the contract's canonical [`TonCellBody`] / [`TonCellRefs`] (pure data,
/// produced by [`crate::ton::normalize_body_boc`]); only [`TonAddress`] is
/// inspector-side, to keep the workchain decoupled from the contract enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonLog {
    pub from_address: TonAddress,
    pub body: TonCellBody,
    pub body_refs: TonCellRefs,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TonExtractedValue {
    Log(TonLog),
}
