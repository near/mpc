use ed25519_dalek::{SigningKey, VerifyingKey};
use std::str::FromStr;

use contract_interface::types as contract_types;
use mpc_contract::{primitives::key_state::Keyset, state::ProtocolContractState};
use mpc_node::migration_service::web::client;

use crate::{ports, types};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to get domain registry: {0}")]
    DomainRegistry(mpc_contract::errors::Error),

    #[error("Incorrect contract state")]
    ContractState,
}

pub struct MpcP2PClient {
    mpc_node_url: String,
    mpc_node_p2p_key: VerifyingKey,
    p2p_private_key: SigningKey,
}

impl MpcP2PClient {
    pub fn new(
        mpc_node_url: String,
        mpc_node_p2p_key: String,
        p2p_private_key: SigningKey,
    ) -> Self {
        let mpc_node_p2p_key = contract_types::Ed25519PublicKey::from_str(&mpc_node_p2p_key)
            .expect("Invalid mpc_node_p2p_key value");
        let mpc_node_p2p_key = VerifyingKey::from_bytes(mpc_node_p2p_key.as_bytes()).unwrap();
        Self {
            mpc_node_url,
            mpc_node_p2p_key,
            p2p_private_key,
        }
    }
}

impl ports::P2PClient for MpcP2PClient {
    type Error = Error;

    async fn get_keyshares(
        &self,
        contract_state: &ProtocolContractState,
    ) -> Result<types::KeyShares, Self::Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            &self.mpc_node_url,
            &self.mpc_node_p2p_key,
        )
        .await
        .unwrap();

        let keyset = match contract_state {
            ProtocolContractState::NotInitialized | ProtocolContractState::Resharing(_) => {
                return Err(Error::ContractState);
            }
            ProtocolContractState::Initializing(state) => {
                Keyset::new(state.epoch_id, state.generated_keys.clone())
            }
            ProtocolContractState::Running(state) => state.keyset.clone(),
        };

        let keyshares = client::make_keyshare_get_request(&mut send_request, &keyset)
            .await
            .unwrap();
        Ok(types::KeyShares(keyshares))
    }

    async fn put_keyshares(&self, keyshares: &types::KeyShares) -> Result<(), Self::Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            &self.mpc_node_url,
            &self.mpc_node_p2p_key,
        )
        .await
        .unwrap();
        client::make_set_keyshares_request(&mut send_request, &keyshares.0)
            .await
            .unwrap();
        Ok(())
    }
}
