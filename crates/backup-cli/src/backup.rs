use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as contract_types;
use rand_core::OsRng;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use tokio::fs::File;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

use crate::{
    adapters, cli, keyset::keyset_to_backup, ports, service::Service, types::PersistentSecrets,
};

pub async fn run_command(args: cli::Args) {
    match args.command {
        cli::Command::GenerateKeys(_) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_write(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");
            generate_secrets(&secrets_storage).await;
        }
        cli::Command::Register(command_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");

            print_register_command(
                &secrets_storage,
                &command_args.near_network,
                &command_args.mpc_contract_account_id,
                &command_args.signer_account_id,
            )
            .await;
        }

        cli::Command::GetKeyshares(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let (mpc_p2p_client, key_shares_storage) =
                open_node_client_and_storage(&home_dir, &subcommand_args).await;

            let mpc_contract =
                adapters::contract_state_fixture::ContractStateFixture::new(home_dir);
            get_keyshares(&mpc_p2p_client, &key_shares_storage, &mpc_contract)
                .await
                .expect("failed to get and store keyshares");
        }
        cli::Command::PutKeyshares(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let (mpc_p2p_client, key_shares_storage) =
                open_node_client_and_storage(&home_dir, &subcommand_args).await;

            put_keyshares(&mpc_p2p_client, &key_shares_storage)
                .await
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to put keyshares from {}: {err:?}",
                        home_dir.display()
                    )
                });
        }
        cli::Command::Run(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let (mpc_p2p_client, key_shares_storage) =
                open_node_client_and_storage(&home_dir, &subcommand_args.node).await;

            let contract_state_reader = adapters::contract_state_rpc::RpcContractStateReader::new(
                &subcommand_args.rpc_url,
                &subcommand_args.near_chain_id,
                subcommand_args.mpc_contract_account_id,
            );
            let request_timeout = Duration::from_secs(subcommand_args.node.request_timeout_seconds);
            probe_contract_state(&contract_state_reader, request_timeout)
                .await
                .expect("NEAR RPC endpoint probe failed");

            let contract_state =
                adapters::contract_state_polling::PollingContractStateWatcher::spawn(
                    contract_state_reader,
                    Duration::from_secs(subcommand_args.poll_interval_seconds),
                    request_timeout,
                )
                .await;

            let (status_reporter, status) = adapters::web::status_channel();
            if let Some(listen_address) = subcommand_args.listen_address {
                adapters::web::spawn_web_server(listen_address, status)
                    .await
                    .expect("failed to start the web server");
            }

            let shutdown = CancellationToken::new();
            spawn_shutdown_on_signal(shutdown.clone());

            run_backup_service(
                mpc_p2p_client,
                key_shares_storage,
                contract_state,
                status_reporter,
                Duration::from_secs(subcommand_args.poll_interval_seconds),
                shutdown,
            )
            .await
            .expect("automatic backup service failed");
        }
    }
}

/// Opens the two adapters every keyshare exchange needs: a client for the MPC node, and local
/// keyshare storage
async fn open_node_client_and_storage(
    home_dir: &Path,
    args: &cli::NodeConnectionArgs,
) -> (
    adapters::p2p_client::MpcP2PClient,
    adapters::keyshare_storage::KeyshareStorageAdapter,
) {
    let secrets_storage =
        adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(home_dir)
            .await
            .expect("failed to create secrets storage");

    let secrets = ports::SecretsRepository::load_secrets(&secrets_storage)
        .await
        .expect("failed to load secrets");

    let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
        args.mpc_node_address.clone(),
        verifying_key_from_str(&args.mpc_node_p2p_key),
        secrets.p2p_private_key,
        mpc_node::config::hex_to_binary_key(&args.backup_encryption_key_hex)
            .expect("require valid hex key"),
        Duration::from_secs(args.request_timeout_seconds),
    );

    let keyshares_storage = adapters::keyshare_storage::KeyshareStorageAdapter::new(
        home_dir.to_path_buf(),
        secrets.local_storage_aes_key,
    )
    .await
    .expect("failed to create keyshare storage");

    (mpc_p2p_client, keyshares_storage)
}

/// Reads the contract state once, so a misconfigured RPC endpoint fails startup with an
/// actionable error instead of a one-time `warn` from the poller and a service that runs
/// without ever backing anything up.
async fn probe_contract_state(
    contract_state: &impl ports::ReadContractState,
    read_timeout: Duration,
) -> anyhow::Result<()> {
    match tokio::time::timeout(read_timeout, contract_state.get_contract_state()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(anyhow::anyhow!(
            "could not read the MPC contract state: {err:?}; check that BACKUP_RPC_URL points \
             to a NEAR JSON-RPC endpoint of the configured chain and that \
             MPC_CONTRACT_ACCOUNT_ID names the MPC contract"
        )),
        Err(_elapsed) => Err(anyhow::anyhow!(
            "the RPC endpoint did not answer within {read_timeout:?}; check that \
             BACKUP_RPC_URL points to a reachable NEAR JSON-RPC endpoint"
        )),
    }
}

/// Backs up keyshares whenever the observed contract state stops being covered by what is
/// stored, until `shutdown` is cancelled. A failed backup is re-attempted after `retry_delay`,
/// since the contract state it failed on may not change again for a long time.
pub async fn run_backup_service(
    mpc_p2p_client: impl ports::P2PClient,
    keyshares_storage: impl ports::KeyShareRepository,
    contract_state: impl ports::WatchContractState,
    status: impl ports::ReportBackupStatus,
    retry_delay: Duration,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    Service::new(
        mpc_p2p_client,
        keyshares_storage,
        contract_state,
        status,
        retry_delay,
    )
    .await?
    .run(shutdown)
    .await
}

fn spawn_shutdown_on_signal(shutdown: CancellationToken) {
    let mut sigterm = signal(SignalKind::terminate())
        .inspect_err(
            |err| tracing::error!(%err, "failed to install SIGTERM handler, graceful shutdown on SIGTERM disabled"),
        )
        .ok();

    tokio::spawn(async move {
        let sigterm_received = async {
            match sigterm.as_mut() {
                Some(sigterm) => {
                    sigterm.recv().await;
                }
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm_received => {}
        }
        shutdown.cancel();
    });
}

pub async fn generate_secrets(secrets_storage: &impl ports::SecretsRepository) {
    let persistent_secrets = PersistentSecrets::generate(&mut OsRng);
    secrets_storage
        .store_secrets(&persistent_secrets)
        .await
        .expect("fail to store private key");
}

async fn print_register_command(
    secrets_storage: &impl ports::SecretsRepository,
    near_network: &str,
    mpc_contract_account_id: &AccountId,
    signer_account_id: &AccountId,
) {
    let secrets = secrets_storage
        .load_secrets()
        .await
        .expect("failed to load secrets");

    let public_key =
        contract_types::Ed25519PublicKey::from(&secrets.p2p_private_key.verifying_key());
    let public_key_str = String::from(&public_key);

    println!("Run the following command to register your backup service:\n");
    println!(
        r#"near contract call-function as-transaction \
  {} \
  register_backup_service \
  json-args '{{"backup_service_info":{{"public_key":"{}"}}}}' \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '1 yoctoNEAR' \
  sign-as {} \
  network-config {} \
  sign-with-keychain \
  send"#,
        mpc_contract_account_id, public_key_str, signer_account_id, near_network
    );
}

pub async fn get_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
    mpc_contract: &impl ports::ReadContractState,
) -> anyhow::Result<()> {
    let contract_state = mpc_contract
        .get_contract_state()
        .await
        .map_err(|err| anyhow::anyhow!("could not get contract state: {err:?}"))?;
    let keyset = keyset_to_backup(&contract_state)?;
    let keyshares = mpc_p2p_client
        .get_keyshares(&keyset)
        .await
        .map_err(|err| anyhow::anyhow!("failed to get keyshares: {err:?}"))?;
    keyshares_storage
        .store_keyshares(&keyshares)
        .await
        .map_err(|err| anyhow::anyhow!("failed to store keyshares: {err:?}"))
}

/// Sends the locally stored keyshares to an MPC node. Fails on an empty local store rather than
/// issuing a request the node would accept and then ignore.
pub async fn put_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
) -> anyhow::Result<()> {
    let key_shares = keyshares_storage
        .load_keyshares()
        .await
        .map_err(|err| anyhow::anyhow!("failed to load keyshares: {err:?}"))?;
    if key_shares.is_empty() {
        anyhow::bail!(
            "no keyshares in local storage: run `get-keyshares` against a node that holds them \
             before putting them back"
        );
    }
    mpc_p2p_client
        .put_keyshares(&key_shares)
        .await
        .map_err(|err| anyhow::anyhow!("failed to put keyshares: {err:?}"))
}

fn verifying_key_from_str(mpc_node_p2p_key: &str) -> VerifyingKey {
    let mpc_node_p2p_key = contract_types::Ed25519PublicKey::from_str(mpc_node_p2p_key)
        .expect("invalid mpc_node_p2p_key value");
    VerifyingKey::from_bytes(mpc_node_p2p_key.as_bytes()).expect("Invalid mpc_node_p2p_key value")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use mpc_node::keyshare::{Keyshare, test_utils::generate_dummy_keyshare};
    use near_mpc_contract_interface::types::{Keyset, ProtocolContractState};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::{probe_contract_state, put_keyshares};
    use crate::ports::{KeyShareRepository, P2PClient, ReadContractState};
    use crate::test_utils::running_state_with_epoch;

    struct FakeP2PClient {
        put_keyshares_calls: AtomicUsize,
    }

    impl FakeP2PClient {
        fn new() -> Self {
            Self {
                put_keyshares_calls: AtomicUsize::new(0),
            }
        }
    }

    impl P2PClient for FakeP2PClient {
        type Error = anyhow::Error;

        async fn get_keyshares(&self, _keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
            unreachable!("put-keyshares never fetches")
        }

        async fn put_keyshares(&self, _key_shares: &[Keyshare]) -> Result<(), Self::Error> {
            self.put_keyshares_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeKeyshareStorage {
        keyshares: Vec<Keyshare>,
    }

    impl KeyShareRepository for FakeKeyshareStorage {
        type Error = anyhow::Error;

        async fn store_keyshares(&self, _key_shares: &[Keyshare]) -> Result<(), Self::Error> {
            unreachable!("put-keyshares never stores")
        }

        async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
            Ok(self.keyshares.clone())
        }
    }

    /// Answers every read with `response`, or never answers when there is none.
    struct FakeContractStateReader {
        response: Option<Result<ProtocolContractState, &'static str>>,
    }

    impl FakeContractStateReader {
        fn answering(response: Result<ProtocolContractState, &'static str>) -> Self {
            Self {
                response: Some(response),
            }
        }

        fn hanging() -> Self {
            Self { response: None }
        }
    }

    impl ReadContractState for FakeContractStateReader {
        type Error = &'static str;

        async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
            match &self.response {
                Some(response) => response.clone(),
                None => std::future::pending().await,
            }
        }
    }

    const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn probe_contract_state__should_pass_when_the_contract_state_is_readable() {
        // Given
        let reader = FakeContractStateReader::answering(Ok(running_state_with_epoch(5)));

        // When
        let result = probe_contract_state(&reader, PROBE_TIMEOUT).await;

        // Then
        result.expect("a readable contract state should pass the probe");
    }

    #[tokio::test]
    async fn probe_contract_state__should_fail_when_the_endpoint_cannot_be_read() {
        // Given
        let reader = FakeContractStateReader::answering(Err("dns error: no such host"));

        // When
        let result = probe_contract_state(&reader, PROBE_TIMEOUT).await;

        // Then
        let err = result.expect_err("an unreadable endpoint should fail the probe");
        assert!(
            err.to_string().contains("dns error: no such host"),
            "the cause should be reported: {err}"
        );
        assert!(
            err.to_string().contains("BACKUP_RPC_URL"),
            "the misconfigured setting should be named: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_contract_state__should_fail_when_the_endpoint_does_not_answer_in_time() {
        // Given
        let reader = FakeContractStateReader::hanging();

        // When
        let result = probe_contract_state(&reader, PROBE_TIMEOUT).await;

        // Then
        let err = result.expect_err("an endpoint that never answers should fail the probe");
        assert!(
            err.to_string().contains("BACKUP_RPC_URL"),
            "the misconfigured setting should be named: {err}"
        );
    }

    #[tokio::test]
    async fn put_keyshares__should_send_the_stored_keyshares() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let mpc_p2p_client = FakeP2PClient::new();
        let storage = FakeKeyshareStorage {
            keyshares: vec![generate_dummy_keyshare(1, 0, 1, &mut rng)],
        };

        // When
        let result = put_keyshares(&mpc_p2p_client, &storage).await;

        // Then
        result.expect("stored keyshares should be pushed to the node");
        assert_eq!(mpc_p2p_client.put_keyshares_calls.load(Ordering::SeqCst), 1);
    }
}
