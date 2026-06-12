use near_mpc_contract_interface::types::AptosEvent;

pub mod inspector;

mpc_primitives::define_hash!(AptosTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AptosExtractedValue {
    Event(AptosEvent),
}
