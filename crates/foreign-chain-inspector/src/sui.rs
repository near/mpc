use near_mpc_contract_interface::types::SuiEvent;

pub mod inspector;

/// Sui mainnet's genesis checkpoint digest in base58, exactly as `get_service_info`
/// reports it. The first four bytes are the well known chain identifier `0x35834a8a`,
/// the value to grep against Sui docs when verifying this.
pub const MAINNET_GENESIS_CHECKPOINT_DIGEST: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
/// Sui testnet's counterpart of [`MAINNET_GENESIS_CHECKPOINT_DIGEST`], chain identifier
/// `0x4c78adac`.
pub const TESTNET_GENESIS_CHECKPOINT_DIGEST: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";

mpc_primitives::define_hash!(SuiTransactionDigest, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuiExtractedValue {
    Event(SuiEvent),
}
