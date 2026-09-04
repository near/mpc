//! Inspection of Solana Virtual Machine (SVM) chains: Solana and Fogo.

use near_mpc_contract_interface::types::{SvmAccount, SvmInnerInstruction};

pub mod inspector;

mpc_primitives::define_hash!(SvmTransactionSignature, 64);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SvmExtractedValue {
    InnerInstruction(SvmInnerInstruction),
    AccountState(SvmAccount),
}
