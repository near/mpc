//! Inspection of Solana Virtual Machine (SVM) chains: Solana and Fogo.

use near_mpc_contract_interface::types::{SvmAccount, SvmInnerInstruction};

pub mod inspector;

mpc_primitives::define_hash!(SvmTransactionSignature, 64);

/// An SVM network's identity: providers report their genesis block hash as the network fingerprint.
pub const SOLANA_MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
/// Solana devnet's counterpart of [`SOLANA_MAINNET_GENESIS_HASH`].
pub const SOLANA_DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
pub const FOGO_MAINNET_GENESIS_HASH: &str = "CDLtwKnaCoK157uaHQDj4fHu72AyD2519Cphmpiq6hvT";
/// Fogo testnet's counterpart of [`FOGO_MAINNET_GENESIS_HASH`].
pub const FOGO_TESTNET_GENESIS_HASH: &str = "9GGSFo95raqzZxWqKM5tGYvJp5iv4Dm565S4r8h5PEu9";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SvmExtractedValue {
    InnerInstruction(SvmInnerInstruction),
    AccountState(SvmAccount),
}
