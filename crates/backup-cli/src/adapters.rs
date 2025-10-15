struct DummySecretsStorage {}

impl SecretsRepository for DummySecretsStorage {
    type Error = !;

    async fn store_private_key(&self, _private_key: &types::PrivateKey) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_private_key(&self) -> Result<types::PrivateKey, Self::Error> {
        Ok(types::PrivateKey {})
    }
}

struct DummyKeyshareRepository {}

impl KeyShareRepository for DummyKeyshareRepository {
    type Error = !;

    async fn store_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }
}

struct DummyP2PClient {}

impl P2PClient for DummyP2PClient {
    type Error = !;

    async fn get_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }

    async fn put_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DummyContractInterface {}

impl ContractInterface for DummyContractInterface {
    type Error = !;

    async fn register_backup_data(
        &self,
        _public_key: &types::PublicKey,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
