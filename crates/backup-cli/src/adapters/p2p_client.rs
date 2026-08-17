use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_node::{config::AesKey256, keyshare::Keyshare, migration_service::web::client};
use near_mpc_contract_interface::types::Keyset;
use tokio::time::timeout;

use std::future::Future;

use crate::{cli::NodeAddress, ports};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("GET keyshares request to MPC node failed: {0}")]
    GetRequest(anyhow::Error),

    #[error("PUT keyshares request to MPC node failed: {0}")]
    PutRequest(anyhow::Error),

    #[error("connection to MPC node failed: {0}")]
    ServerConnection(anyhow::Error),

    #[error("request to MPC node did not finish within {0:?}")]
    Timeout(Duration),
}

pub struct MpcP2PClient {
    mpc_node_address: NodeAddress,
    mpc_node_p2p_key: VerifyingKey,
    p2p_private_key: SigningKey,
    backup_encryption_key: AesKey256,
    request_timeout: Duration,
}

impl MpcP2PClient {
    pub fn new(
        mpc_node_address: NodeAddress,
        mpc_node_p2p_key: VerifyingKey,
        p2p_private_key: SigningKey,
        backup_encryption_key: AesKey256,
        request_timeout: Duration,
    ) -> Self {
        Self {
            mpc_node_address,
            mpc_node_p2p_key,
            p2p_private_key,
            backup_encryption_key,
            request_timeout,
        }
    }
}

impl ports::P2PClient for MpcP2PClient {
    type Error = Error;

    async fn get_keyshares(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
        self.within_deadline(self.get_keyshares_unbounded(keyset))
            .await
    }

    async fn put_keyshares(&self, keyshares: &[Keyshare]) -> Result<(), Self::Error> {
        self.within_deadline(self.put_keyshares_unbounded(keyshares))
            .await
    }
}

impl MpcP2PClient {
    async fn within_deadline<T>(
        &self,
        request: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        timeout(self.request_timeout, request)
            .await
            .map_err(|_elapsed| Error::Timeout(self.request_timeout))?
    }

    async fn get_keyshares_unbounded(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            self.mpc_node_address.to_string(),
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

    async fn put_keyshares_unbounded(&self, keyshares: &[Keyshare]) -> Result<(), Error> {
        let mut send_request = client::connect_to_web_server(
            &self.p2p_private_key,
            self.mpc_node_address.to_string(),
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
        .map_err(Error::PutRequest)?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use mpc_node::keyshare::test_utils::KeysetBuilder;
    use mpc_node::migration_service::web::test_utils;
    use mpc_node::p2p::testing::port_seed;

    use assert_matches::assert_matches;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng as _;
    use std::time::Duration;

    use crate::adapters::p2p_client::{Error, MpcP2PClient};
    use crate::cli::NodeAddress;
    use crate::ports::P2PClient;

    /// Long enough that no passing test can hit it; the timeout test passes its own.
    const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn test_get_keyshares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let test_setup = test_utils::setup(port_seed::BACKUP_CLI_WEBSERVER_GET_KEYSHARES).await;
        let addr: NodeAddress = test_setup.target_address.to_string().parse().unwrap();
        let client = MpcP2PClient::new(
            addr,
            test_setup.server_key.verifying_key(),
            test_setup.client_key,
            test_setup.backup_encryption_key,
            TEST_REQUEST_TIMEOUT,
        );
        let keyset_builder = KeysetBuilder::new_populated(0, 8, &mut rng);
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
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let mut test_setup = test_utils::setup(port_seed::BACKUP_CLI_WEBSERVER_PUT_KEYSHARES).await;
        let addr: NodeAddress = test_setup.target_address.to_string().parse().unwrap();
        let client = MpcP2PClient::new(
            addr,
            test_setup.server_key.verifying_key(),
            test_setup.client_key,
            test_setup.backup_encryption_key,
            TEST_REQUEST_TIMEOUT,
        );
        let keyset_builder = KeysetBuilder::new_populated(0, 8, &mut rng);
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

    #[tokio::test]
    async fn get_keyshares__should_fail_when_the_node_never_completes_the_request() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given a listener that accepts the connection and never speaks TLS, so the request
        // cannot finish and nothing else bounds it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: NodeAddress = listener.local_addr().unwrap().to_string().parse().unwrap();
        let accepted = tokio::spawn(async move {
            let held = listener.accept().await;
            std::future::pending::<()>().await;
            drop(held);
        });
        let client = MpcP2PClient::new(
            addr,
            SigningKey::generate(&mut rng).verifying_key(),
            SigningKey::generate(&mut rng),
            [7u8; 32],
            Duration::from_millis(50),
        );
        let keyset = KeysetBuilder::new_populated(0, 8, &mut rng).keyset();

        // When
        let err = client
            .get_keyshares(&keyset)
            .await
            .expect_err("a request past the deadline should fail");

        // Then
        assert_matches!(err, Error::Timeout(_));
        accepted.abort();
    }

    #[tokio::test]
    async fn test_put_keyshares_with_hostname() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        // Given
        let mut test_setup =
            test_utils::setup(port_seed::BACKUP_CLI_WEBSERVER_PUT_KEYSHARES_HOSTNAME).await;
        let addr: NodeAddress = format!("localhost:{}", test_setup.target_address.port())
            .parse()
            .unwrap();
        let client = MpcP2PClient::new(
            addr,
            test_setup.server_key.verifying_key(),
            test_setup.client_key,
            test_setup.backup_encryption_key,
            TEST_REQUEST_TIMEOUT,
        );
        let keyset_builder = KeysetBuilder::new_populated(0, 8, &mut rng);
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
