use crate::types::{AccountId, BlockHeight, MpcNode, NodeReport, 
    ReportedData, Timestamp, TlsKey, UserId, WhitelistedAccount};

pub trait WhitelistAccounts{ 
    fn add(&self, account_id: AccountId, added_by: UserId, added_at: Timestamp); 
    fn remove(&self, account_id: AccountId);
    fn is_whitelisted(&self, account_id: AccountId) -> Option<WhitelistedAccount>;
    fn list(&self) -> Vec<WhitelistedAccount>;}

pub trait TrackMpcNodes{
    fn add(&self, account_id: AccountId, tls_key: TlsKey, block_height: BlockHeight, added_at: Timestamp); 
    fn remove(&self, tls_key: TlsKey);
    fn list(&self) -> Vec<MpcNode>;}

pub trait StoreReports{ 
    fn add(&self,account_id: AccountId, tls_key: TlsKey, node_report: NodeReport, received_at: Timestamp); 
    fn latest(&self, tls_key: TlsKey) -> Option<ReportedData>; 
    fn history(&self, account_id: AccountId, limit: u32) -> Vec<ReportedData>;}