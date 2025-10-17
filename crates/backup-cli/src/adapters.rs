use ed25519_dalek::VerifyingKey;

use crate::{
    ports::{ContractInterface, KeyShareRepository, P2PClient},
    types,
};

pub mod secrets_storage;

pub struct DummyKeyshareStorage {}

impl KeyShareRepository for DummyKeyshareStorage {
    type Error = String;

    async fn store_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }
}

pub struct DummyP2PClient {}

impl P2PClient for DummyP2PClient {
    type Error = String;

    async fn get_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }

    async fn put_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct DummyContractInterface {}

impl ContractInterface for DummyContractInterface {
    type Error = String;

    async fn register_backup_data(&self, _public_key: &VerifyingKey) -> Result<(), Self::Error> {
        Ok(())
    }
}
