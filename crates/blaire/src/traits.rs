use crate::types::{
    AccountId, BlockHeight, MpcNode, NodeReport, ReportedData, Timestamp, TlsKey, UserId,
    WhitelistedAccount,
};

pub trait WhitelistAccounts {
    type Error;
    fn add_account(&self, account_id: AccountId, added_by: UserId, added_at: Timestamp) -> Result<(), Self::Error>;
    fn remove_account(&self, account_id: &AccountId) -> Result<(), Self::Error>;
    fn is_whitelisted(&self, account_id: &AccountId) -> Result<Option<WhitelistedAccount>, Self::Error>;
    fn list_account(&self) -> Result<Vec<WhitelistedAccount>, Self::Error>;
}

pub trait TrackMpcNodes {
    type Error;
    fn add_node(
        &self,
        account_id: AccountId,
        tls_key: TlsKey,
        block_height: BlockHeight,
        added_at: Timestamp,
    ) -> Result<(), Self::Error>;
    fn remove_node(&self, tls_key: &TlsKey) -> Result<(), Self::Error>;
    fn list_nodes(&self) -> Result<Vec<MpcNode>, Self::Error>;
}

pub trait StoreReports {
    type Error;
    fn add_report(
        &self,
        account_id: AccountId,
        tls_key: TlsKey,
        node_report: NodeReport,
        received_at: Timestamp,
    ) -> Result<(), Self::Error>;
    fn latest_report(&self, tls_key: &TlsKey) -> Result<Option<ReportedData>, Self::Error>;
    fn list_reports(&self, account_id: &AccountId, limit: u32) -> Result<Vec<ReportedData>, Self::Error>;
}
