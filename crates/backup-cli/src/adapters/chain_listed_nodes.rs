use std::time::Duration;

use anyhow::Context as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_node::{config::AesKey256, keyshare::Keyshare, parse_participant_address};
use near_account_id::AccountId;
use near_contract_transport::ViewContract;
use near_mpc_contract_interface::{
    client::MpcContractHandle,
    types::{Keyset, ParticipantInfo},
};

use crate::{adapters::p2p_client::MpcP2PClient, cli::NodeAddress, ports};

/// Exchanges keyshares only with the MPC nodes the contract lists for an account, at the hosts of
/// their contract URLs and verified by the TLS keys the contract lists for them: backups come from
/// the account's participant node, and keyshares go to its attested migration destination.
#[derive(Clone)]
pub struct ChainListedNodes<V> {
    contract: MpcContractHandle<V>,
    account_id: AccountId,
    migration_port: u16,
    p2p_private_key: SigningKey,
    backup_encryption_key: AesKey256,
    request_timeout: Duration,
}

impl<V> ChainListedNodes<V> {
    pub fn new(
        contract: MpcContractHandle<V>,
        account_id: AccountId,
        migration_port: u16,
        p2p_private_key: SigningKey,
        backup_encryption_key: AesKey256,
        request_timeout: Duration,
    ) -> Self {
        Self {
            contract,
            account_id,
            migration_port,
            p2p_private_key,
            backup_encryption_key,
            request_timeout,
        }
    }

    fn client(&self, node: &ParticipantInfo) -> anyhow::Result<MpcP2PClient> {
        let (host, port) = parse_participant_address(&node.url, Some(self.migration_port))?;
        Ok(MpcP2PClient::new(
            NodeAddress::Host(host, port),
            VerifyingKey::try_from(&node.tls_public_key)?,
            self.p2p_private_key.clone(),
            self.backup_encryption_key,
            self.request_timeout,
        ))
    }
}

impl<V: ViewContract + Clone + Send + Sync + 'static> ports::P2PClient for ChainListedNodes<V> {
    type Error = anyhow::Error;

    async fn get_keyshares(&self, keyset: &Keyset) -> anyhow::Result<Vec<Keyshare>> {
        let node = self
            .contract
            .participant_info(self.account_id.clone())
            .await?
            .value
            .context("the contract lists no participant for the account")?;
        Ok(self.client(&node)?.get_keyshares(keyset).await?)
    }

    async fn put_keyshares(&self, keyshares: &[Keyshare]) -> anyhow::Result<()> {
        let destination = self
            .contract
            .attested_migration_destination(self.account_id.clone())
            .await?
            .value
            .context("the account has no attested migration destination")?;
        Ok(self
            .client(&destination.destination_node_info)?
            .put_keyshares(keyshares)
            .await?)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use mpc_node::{
        keyshare::test_utils::KeysetBuilder,
        migration_service::web::test_utils::{TestSetup, setup},
        p2p::testing::{TestPorts, port_seed},
    };
    use near_contract_transport::mock::{MockViewContract, MockViewError};
    use near_mpc_contract_interface::method_names::{
        ATTESTED_MIGRATION_DESTINATION, PARTICIPANT_INFO,
    };
    use rand::{SeedableRng as _, rngs::StdRng};
    use rstest::rstest;
    use serde::Serialize;

    use super::*;
    use crate::{
        ports::P2PClient as _,
        test_utils::{
            TEST_REQUEST_TIMEOUT, migration_destination, mpc_contract, observed,
            operator_account_id, participant_info,
        },
    };

    /// Lists the given node for the account in the given view; every other view fails
    fn chain_listed_nodes(
        test_setup: &TestSetup,
        view: &str,
        listed: &impl Serialize,
    ) -> ChainListedNodes<MockViewContract> {
        let viewer = MockViewContract::new(Err(MockViewError("not listed")));
        viewer.set_view_response_for_method(view, observed(&Some(listed)));
        ChainListedNodes::new(
            mpc_contract(viewer),
            operator_account_id(),
            test_setup.target_address.port(),
            test_setup.client_key.clone(),
            test_setup.backup_encryption_key,
            TEST_REQUEST_TIMEOUT,
        )
    }

    #[rstest]
    #[case::listed_key(port_seed::BACKUP_CLI_CHAIN_LISTED_NODES_LISTED_KEY, true)]
    #[case::other_key(port_seed::BACKUP_CLI_CHAIN_LISTED_NODES_OTHER_KEY, false)]
    #[tokio::test]
    async fn chain_listed_nodes__should_get_keyshares_only_from_the_listed_tls_key(
        #[case] ports: TestPorts,
        #[case] node_key_listed: bool,
    ) {
        // Given
        let mut rng = StdRng::seed_from_u64(1);
        let test_setup = setup(ports).await;
        let listed_key = if node_key_listed {
            test_setup.server_key.verifying_key()
        } else {
            SigningKey::generate(&mut rng).verifying_key()
        };
        let nodes = chain_listed_nodes(
            &test_setup,
            PARTICIPANT_INFO,
            &participant_info((&listed_key).into()),
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
        let keyshares = nodes.get_keyshares(&keyset).await.ok();

        // Then
        let expected = node_key_listed.then(|| keyset_builder.keyshares().to_vec());
        assert_eq!(keyshares, expected);
    }

    #[tokio::test]
    async fn chain_listed_nodes__should_put_keyshares_to_the_attested_migration_destination() {
        // Given
        let mut rng = StdRng::seed_from_u64(1);
        let mut test_setup = setup(port_seed::BACKUP_CLI_CHAIN_LISTED_NODES_DESTINATION).await;
        let nodes = chain_listed_nodes(
            &test_setup,
            ATTESTED_MIGRATION_DESTINATION,
            &migration_destination((&test_setup.server_key.verifying_key()).into()),
        );
        let keyshares = KeysetBuilder::new_populated(0, 8, &mut rng)
            .keyshares()
            .to_vec();

        // When
        nodes.put_keyshares(&keyshares).await.unwrap();

        // Then
        assert_eq!(
            *test_setup.import_keyshares_receiver.borrow_and_update(),
            keyshares
        );
    }
}
