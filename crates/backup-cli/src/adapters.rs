use std::str::FromStr;

use contract_interface::types::Ed25519PublicKey;
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

pub struct MpcP2PClient {
    mpc_node_url: String,
    mpc_node_p2p_key: VerifyingKey,
}

impl MpcP2PClient {
    pub fn new(mpc_node_url: String, mpc_node_p2p_key: String) -> Self {
        let mpc_node_p2p_key =
            Ed25519PublicKey::from_str(&mpc_node_p2p_key).expect("Invalid mpc_node_p2p_key value");
        let mpc_node_p2p_key = VerifyingKey::from_bytes(mpc_node_p2p_key.as_bytes()).unwrap();
        Self {
            mpc_node_url,
            mpc_node_p2p_key,
        }
    }
}

impl P2PClient for MpcP2PClient {
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
