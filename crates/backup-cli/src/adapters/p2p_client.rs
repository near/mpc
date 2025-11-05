use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::primitives::key_state::Keyset;
use mpc_node::{config::AesKey256, keyshare::Keyshare, migration_service::web::client};

use crate::ports;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed maket GET keyshares request: {0}")]
    GetRequest(anyhow::Error),

    #[error("failed maket PUT keyshares request: {0}")]
    PutRequest(anyhow::Error),

    #[error("failed maket PUT keyshares request: {0}")]
    ServerConnection(anyhow::Error),
}

pub struct MpcP2PClient {
    mpc_node_url: String,
    mpc_node_p2p_key: VerifyingKey,
    p2p_private_key: SigningKey,
    backup_encryption_key: AesKey256,
}

impl MpcP2PClient {
    pub fn new(
        mpc_node_url: String,
        mpc_node_p2p_key: VerifyingKey,
        p2p_private_key: SigningKey,
        backup_encryption_key: AesKey256,
    ) -> Self {
        Self {
            mpc_node_url,
            mpc_node_p2p_key,
            p2p_private_key,
            backup_encryption_key,
        }
    }
}

impl ports::P2PClient for MpcP2PClient {
    type Error = Error;

    async fn get_keyshares(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            &self.mpc_node_url,
            &self.mpc_node_p2p_key,
        )
        .await
        .map_err(Error::ServerConnection)?;

        let keyshares = client::make_keyshare_get_request(
            &mut send_request,
            keyset,
            &self.backup_encryption_key,
        )
        .await
        .map_err(Error::GetRequest)?;
        Ok(keyshares)
    }

    async fn put_keyshares(&self, keyshares: &[Keyshare]) -> Result<(), Self::Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            &self.mpc_node_url,
            &self.mpc_node_p2p_key,
        )
        .await
        .map_err(Error::ServerConnection)?;
        client::make_set_keyshares_request(
            &mut send_request,
            keyshares,
            &self.backup_encryption_key,
        )
        .await
        .map_err(Error::GetRequest)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mpc_node::migration_service::web::test_utils;
    use mpc_node::p2p::testing::PortSeed;

    use crate::adapters::p2p_client::MpcP2PClient;
    use crate::ports::P2PClient;
    use mpc_node::keyshare::test_utils::KeysetBuilder;

    #[tokio::test]
    async fn test_get_keyshares() {
        // Given
        let test_setup = test_utils::setup(PortSeed::BACKUP_CLI_WEBSERVER_GET_KEYSHARES).await;
        let client = MpcP2PClient::new(
            test_setup.target_address,
            test_setup.server_key.verifying_key(),
            test_setup.client_key,
            test_setup.backup_encryption_key,
        );
        let keyset_builder = KeysetBuilder::new_populated(0, 8);
        let keyset = keyset_builder.keyset();

        test_setup
            .keyshare_storage
            .write()
            .await
            .import_backup(keyset_builder.keyshares().to_vec(), &keyset)
            .await
            .unwrap();

        // When
        let keyshares = client.get_keyshares(&keyset).await.unwrap();

        // Then
        let expected_keyshares = test_setup
            .keyshare_storage
            .read()
            .await
            .get_keyshares(&keyset)
            .await
            .unwrap();
        assert_eq!(keyshares, expected_keyshares);
    }

    #[tokio::test]
    async fn test_put_keyshares() {
        // Given
        let mut test_setup = test_utils::setup(PortSeed::BACKUP_CLI_WEBSERVER_PUT_KEYSHARES).await;
        let client = MpcP2PClient::new(
            test_setup.target_address,
            test_setup.server_key.verifying_key(),
            test_setup.client_key,
            test_setup.backup_encryption_key,
        );
        let keyset_builder = KeysetBuilder::new_populated(0, 8);
        let keyshares = keyset_builder.keyshares().to_vec();

        // When
        client.put_keyshares(&keyshares).await.unwrap();

        // Then
        let expected_keyshares = test_setup
            .import_keyshares_receiver
            .borrow_and_update()
            .clone();

        assert_eq!(keyshares, expected_keyshares);
    }
}
