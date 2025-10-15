use crate::{
    ports::{ContractInterface, KeyShareRepository, P2PClient, SecretsRepository},
    types,
};

pub struct DummySecretsStorage {}

impl SecretsRepository for DummySecretsStorage {
    type Error = String;

    async fn store_private_key(&self, _private_key: &types::PrivateKey) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_private_key(&self) -> Result<types::PrivateKey, Self::Error> {
        Ok(types::PrivateKey {})
    }
}

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

    async fn register_backup_data(
        &self,
        _public_key: &types::PublicKey,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
