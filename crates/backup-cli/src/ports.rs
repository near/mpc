use std::future::Future;

use mpc_node::keyshare::Keyshare;
use near_mpc_contract_interface::types::{Keyset, ProtocolContractState};

use crate::types;

pub trait WatchContractState {
    type Error: std::fmt::Debug;

    /// The last state observed on chain. Marks that state as seen, so a following
    /// [`Self::changed`] waits for the next one.
    fn latest(&mut self) -> Result<ProtocolContractState, Self::Error>;

    /// Waits until the observed state changes. `Err` means no further states will arrive.
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
