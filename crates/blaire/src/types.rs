//! Data types stored by Blaire.

pub use blaire_interface::NodeReport;
pub use near_account_id::AccountId;
pub use near_mpc_crypto_types::Ed25519PublicKey as TlsKey;

pub type UserId = u64;
pub type Timestamp = u64;
pub type BlockHeight = u64;

#[derive(Debug)]
pub struct WhitelistAccount{
    pub account_id: AccountId,
    pub added_by: UserId,
    pub added_at: Timestamp,
}

#[derive(Debug)]
pub struct MpcNode{
    pub account_id: AccountId,
    pub tls_key: TlsKey,
    pub added_at: Timestamp,
    pub block_height: BlockHeight,
}

#[derive(Debug)]
pub struct ReportedData{
    pub account_id: AccountId,
    pub tls_key: TlsKey,
    pub node_report: NodeReport,
    pub received_at: Timestamp,
}
