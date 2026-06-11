// Like Starknet's `StarknetLog`, the extracted log and its address reuse the
// contract DTOs wholesale: they are pure data with no chain-client coupling.
pub use near_mpc_contract_interface::types::{TonAddress, TonLog, TonWorkchain};

mpc_primitives::define_hash!(TonAccountHash, 32);
mpc_primitives::define_hash!(TonTransactionHash, 32);

/// Identifies a TON transaction to inspect: the (basechain) account that
/// produced it plus the transaction hash. The workchain is carried explicitly
/// so non-basechain requests can be rejected before any RPC round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TonTransactionId {
    pub workchain: TonWorkchain,
    pub account: TonAccountHash,
    pub tx_hash: TonTransactionHash,
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
