use near_mpc_contract_interface::types::TonLog;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TonExtractedValue {
    Log(TonLog),
}
