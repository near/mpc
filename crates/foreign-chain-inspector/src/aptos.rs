use near_mpc_contract_interface::types::AptosEvent;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 1;
pub const TESTNET_CHAIN_ID: u64 = 2;

mpc_primitives::define_hash!(AptosTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AptosExtractedValue {
    Event(AptosEvent),
}
