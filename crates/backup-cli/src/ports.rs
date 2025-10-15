use std::future::Future;

use crate::types;

pub trait SecretsRepository {
    type Error: std::error::Error;

    fn store_private_key(
        &self,
        private_key: &types::PrivateKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn load_private_key(
        &self,
    ) -> impl Future<Output = Result<types::PrivateKey, Self::Error>> + Send;
}

pub trait KeyShareRepository {
    type Error: std::error::Error;

    fn store_key_shares(
        &self,
        key_shares: &types::KeyShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn load_key_shares(&self)
    -> impl Future<Output = Result<types::KeyShares, Self::Error>> + Send;
}

pub trait P2PClient {
    type Error: std::error::Error;

    fn get_key_shares(&self) -> impl Future<Output = Result<types::KeyShares, Self::Error>> + Send;
    fn put_key_shares(
        &self,
        key_shares: &types::KeyShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait ContractInterface {
    type Error: std::error::Error;

    fn register_backup_data(
        &self,
        public_key: &types::PublicKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
