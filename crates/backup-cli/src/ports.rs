use std::future::Future;

use mpc_node::keyshare::Keyshare;
use near_mpc_contract_interface::types::{EpochId, Keyset, ProtocolContractState};

use crate::types;

pub trait ReportBackupStatus {
    fn keyset_backed_up(&self, epoch_id: EpochId);
    /// Storage was found to already cover `epoch_id` on startup. Reported separately from
    /// [`Self::keyset_backed_up`] because storage holds no record of when it was written,
    /// so there is no backup time to publish.
    fn keyset_already_backed_up(&self, epoch_id: EpochId);
}

pub trait WatchContractState {
    type Error: std::fmt::Debug;

    fn latest(&mut self) -> Result<ProtocolContractState, Self::Error>;
    fn changed(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
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
