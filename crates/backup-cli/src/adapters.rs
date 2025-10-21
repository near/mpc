use mpc_node::keyshare::Keyshare;

use crate::ports::KeyShareRepository;

pub mod contract_interface;
pub mod p2p_client;
pub mod secrets_storage;

pub struct DummyKeyshareStorage {}

impl KeyShareRepository for DummyKeyshareStorage {
    type Error = String;

    async fn store_keyshares(&self, _key_shares: &[Keyshare]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
        Ok(vec![])
    }
}
