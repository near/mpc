use std::future::Future;

use tokio::sync::watch::error::RecvError;

use mpc_node::keyshare::Keyshare;
use near_mpc_contract_interface::types::{EpochId, Keyset, ProtocolContractState};

use crate::types;

pub trait ReportBackupStatus {
    /// Reported for a new backup and for a fetch that confirms the stored one.
    /// `timestamp_seconds` is `None` when the backup time is unknown, e.g. for a backup
    /// found already on disk.
    fn keyset_backed_up(&self, epoch_id: EpochId, timestamp_seconds: Option<u64>);
}

pub trait GetCurrentTime {
    /// `None` when the system clock is before the Unix epoch.
    fn unix_now_seconds(&self) -> Option<u64>;
}

pub trait SecretsRepository {
    type Error: std::fmt::Debug;

    fn store_secrets(
        &self,
        secrets: &types::PersistentSecrets,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn load_secrets(
        &self,
    ) -> impl Future<Output = Result<types::PersistentSecrets, Self::Error>> + Send;
}

pub trait KeyShareRepository {
    type Error: std::fmt::Debug;

    fn store_keyshares(
        &self,
        key_shares: &[Keyshare],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn load_keyshares(&self) -> impl Future<Output = Result<Vec<Keyshare>, Self::Error>> + Send;
}

pub trait P2PClient {
    type Error: std::fmt::Debug;

    fn get_keyshares(
        &self,
        keyset: &Keyset,
    ) -> impl Future<Output = Result<Vec<Keyshare>, Self::Error>> + Send;
    fn put_keyshares(
        &self,
        key_shares: &[Keyshare],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait ReadContractState {
    type Error: std::fmt::Debug;

    fn get_contract_state(
        &self,
    ) -> impl Future<Output = Result<ProtocolContractState, Self::Error>> + Send;
}

pub trait WatchContractState {
    type Error: std::fmt::Debug;

    /// The latest observed state, or the error the last read failed with. Marks it seen.
    fn latest(&mut self) -> Result<ProtocolContractState, Self::Error>;

    /// Waits for a state not yet seen; errors once nothing observes the contract anymore.
    fn changed(&mut self) -> impl Future<Output = Result<(), RecvError>> + Send;
}
