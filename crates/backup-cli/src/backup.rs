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

            put_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
        cli::Command::Run(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let (mpc_p2p_client, key_shares_storage) =
                open_node_client_and_storage(&home_dir, &subcommand_args.node).await;

            let contract_state =
                adapters::contract_state_polling::PollingContractStateWatcher::spawn(
                    adapters::contract_state_rpc::RpcContractStateReader::new(
                        &subcommand_args.rpc_url,
                        &subcommand_args.near_chain_id,
                        subcommand_args.mpc_contract_account_id,
                    ),
                    Duration::from_secs(subcommand_args.poll_interval_seconds),
                    Duration::from_secs(subcommand_args.node.request_timeout_seconds),
                )
                .await;

            let shutdown = CancellationToken::new();
            spawn_shutdown_on_signal(shutdown.clone());

            run_backup_service(mpc_p2p_client, key_shares_storage, contract_state, shutdown)
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

/// Backs up keyshares whenever the observed contract state stops being covered by what is
/// stored, until `shutdown` is cancelled.
pub async fn run_backup_service(
    mpc_p2p_client: impl ports::P2PClient,
    keyshares_storage: impl ports::KeyShareRepository,
    contract_state: impl ports::WatchContractState,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    Service::new(mpc_p2p_client, keyshares_storage, contract_state)
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

pub async fn put_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
) {
    let key_shares = keyshares_storage
        .load_keyshares()
        .await
        .expect("fail to load key shares");
    mpc_p2p_client
        .put_keyshares(&key_shares)
        .await
        .expect("fail to put key shares");
}

fn verifying_key_from_str(mpc_node_p2p_key: &str) -> VerifyingKey {
    let mpc_node_p2p_key = contract_types::Ed25519PublicKey::from_str(mpc_node_p2p_key)
        .expect("invalid mpc_node_p2p_key value");
    VerifyingKey::from_bytes(mpc_node_p2p_key.as_bytes()).expect("Invalid mpc_node_p2p_key value")
}
