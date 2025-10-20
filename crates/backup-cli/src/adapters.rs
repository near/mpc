use ed25519_dalek::VerifyingKey;

use crate::{
    ports::{ContractInterface, KeyShareRepository},
    types,
};

pub mod p2p_client;
pub mod secrets_storage;

pub struct DummyKeyshareStorage {}

impl KeyShareRepository for DummyKeyshareStorage {
    type Error = String;

    async fn store_keyshares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_keyshares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares(vec![]))
    }
}

pub struct DummyContractInterface {}

impl ContractInterface for DummyContractInterface {
    type Error = String;

    async fn register_backup_data(&self, _public_key: &VerifyingKey) -> Result<(), Self::Error> {
        Ok(())
    }
}
