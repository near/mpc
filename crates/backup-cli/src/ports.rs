use std::future::Future;

use crate::types;

pub trait SecretsRepository {
    fn store_private_key(&self, private_key: types::PrivateKey) -> impl Future<Output = ()> + Send;
    fn load_private_key(&self) -> impl Future<Output = types::PrivateKey> + Send;
}

pub trait KeyShareRepository {
    fn store_key_shares(&self, key_shares: types::KeyShares) -> impl Future<Output = ()> + Send;

    fn load_key_shares(&self) -> impl Future<Output = types::KeyShares> + Send;
}

pub trait P2PClient {
    fn get_key_shares(&self) -> impl Future<Output = types::KeyShares> + Send;
    fn put_key_shares(&self, key_shares: types::KeyShares) -> impl Future<Output = ()> + Send;
}

pub trait ContractInterface {
    fn register_backup_data(&self, public_key: types::PublicKey)
    -> impl Future<Output = ()> + Send;
}
