use near_mpc_contract_interface::types::SuiEvent;

pub mod inspector;

mpc_primitives::define_hash!(SuiTransactionDigest, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuiExtractedValue {
    Event(SuiEvent),
}
