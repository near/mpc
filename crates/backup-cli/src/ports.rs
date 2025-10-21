use std::future::Future;

use ed25519_dalek::VerifyingKey;
use mpc_contract::{primitives::key_state::Keyset, state::ProtocolContractState};
use mpc_node::keyshare::Keyshare;

use crate::types;

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

pub trait ContractInterface {
    type Error: std::fmt::Debug;

    fn register_backup_data(
        &self,
        public_key: &VerifyingKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn get_contract_state(
        &self,
    ) -> impl Future<Output = Result<ProtocolContractState, Self::Error>> + Send;
}
