//! Data types stored by Blaire.

pub use blaire_interface::NodeReport;
pub use near_account_id::AccountId;
pub use near_mpc_crypto_types::Ed25519PublicKey as TlsKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeight(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistedAccount {
    pub account_id: AccountId,
    pub added_by: UserId,
    pub added_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpcNode {
    pub account_id: AccountId,
    pub tls_key: TlsKey,
    pub added_at: Timestamp,
    pub block_height: BlockHeight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedData {
    pub account_id: AccountId,
    pub tls_key: TlsKey,
    pub node_report: NodeReport,
    pub received_at: Timestamp,
}
