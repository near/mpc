use near_mpc_contract_interface::types::{Hash256, TonCellBody, TonCellRefs};

/// Identifies a TON transaction to inspect: the (basechain) account that
/// produced it plus the transaction hash. The workchain is carried explicitly
/// so non-basechain requests can be rejected before any RPC round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TonTransactionId {
    pub workchain: i8,
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

/// A TON address as seen by the inspector. The workchain is a plain `i8` (the
/// value carried by the request); the contract-facing [`TonWorkchain`] enum
/// form is applied at the conversion boundary in
/// [`crate::contract_interface_conversions`], mirroring how the other chains
/// keep inspector-side types separate from the contract DTOs.
///
/// [`TonWorkchain`]: near_mpc_contract_interface::types::TonWorkchain
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonAddress {
    pub workchain: i8,
    pub hash: Hash256,
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
