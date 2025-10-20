use crate::{ports::KeyShareRepository, types};

pub mod contract_interface;
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
