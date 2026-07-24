use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as contract_types;
use rand_core::OsRng;
use std::{path::PathBuf, str::FromStr, time::Duration};
use tokio::fs::File;
use tokio_util::sync::CancellationToken;

use crate::{
    adapters::{self, contract_state_fixture::get_keyset_from_contract_state},
    cli, ports,
    types::PersistentSecrets,
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
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");

            let secrets = ports::SecretsRepository::load_secrets(&secrets_storage)
                .await
                .expect("failed to load secrets");

            let mpc_node_p2p_key = verifying_key_from_str(&subcommand_args.mpc_node_p2p_key);
            let backup_encryption_key =
                mpc_node::config::hex_to_binary_key(&subcommand_args.backup_encryption_key_hex)
                    .expect("require valid hex key");
            let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
                subcommand_args.mpc_node_address,
                mpc_node_p2p_key,
                secrets.p2p_private_key,
                backup_encryption_key,
            );

            let key_shares_storage = adapters::keyshare_storage::KeyshareStorageAdapter::new(
                home_dir.clone(),
                secrets.local_storage_aes_key,
            )
            .await
            .expect("failed to create keyshare storage");

            let mpc_contract =
                adapters::contract_state_fixture::ContractStateFixture::new(home_dir);
            get_keyshares(&mpc_p2p_client, &key_shares_storage, &mpc_contract)
                .await
                .expect("failed to get and store keyshares");
        }
        cli::Command::PutKeyshares(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");

            let secrets = ports::SecretsRepository::load_secrets(&secrets_storage)
                .await
                .expect("failed to load secrets");

            let mpc_node_p2p_key = verifying_key_from_str(&subcommand_args.mpc_node_p2p_key);
            let backup_encryption_key =
                mpc_node::config::hex_to_binary_key(&subcommand_args.backup_encryption_key_hex)
                    .expect("require valid hex key");
            let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
                subcommand_args.mpc_node_address,
                mpc_node_p2p_key,
                secrets.p2p_private_key,
                backup_encryption_key,
            );

            let key_shares_storage = adapters::keyshare_storage::KeyshareStorageAdapter::new(
                home_dir,
                secrets.local_storage_aes_key,
            )
            .await
            .expect("failed to create keyshare storage");

            put_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
        cli::Command::Run(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            run_service_command(home_dir, subcommand_args).await;
        }
    }
}

async fn run_service_command(home_dir: PathBuf, args: cli::RunArgs) {
    let secrets_storage =
        adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(home_dir.as_path())
            .await
            .expect("failed to create secrets storage");
    let secrets = ports::SecretsRepository::load_secrets(&secrets_storage)
        .await
        .expect("failed to load secrets");

    let mpc_node_p2p_key = verifying_key_from_str(&args.mpc_node_p2p_key);
    let backup_encryption_key =
        mpc_node::config::hex_to_binary_key(&args.backup_encryption_key_hex)
            .expect("require valid hex key");
    let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
        args.mpc_node_address,
        mpc_node_p2p_key,
        secrets.p2p_private_key,
        backup_encryption_key,
    );

    let key_shares_storage = adapters::keyshare_storage::KeyshareStorageAdapter::new(
        home_dir.clone(),
        secrets.local_storage_aes_key,
    )
    .await
    .expect("failed to create keyshare storage");

    let mpc_contract = adapters::contract_state_rpc::RpcContractStateReader::new(
        &args.rpc_url,
        &args.near_chain_id,
        args.mpc_contract_account_id,
    );

    let shutdown = CancellationToken::new();
    let shutdown_on_signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown_on_signal.cancel();
        }
    });

    if let Err(err) = crate::service::run_service(
        &mpc_p2p_client,
        &key_shares_storage,
        &mpc_contract,
        Duration::from_secs(args.poll_interval_seconds),
        shutdown,
    )
    .await
    {
        tracing::error!(?err, "automatic backup service exited with error");
    }
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
    mpc_contract: &impl ports::ContractStateReader,
) -> anyhow::Result<()> {
    let contract_state = mpc_contract
        .get_contract_state()
        .await
        .map_err(|err| anyhow::anyhow!("could not get contract state: {err:?}"))?;
    let keyset = get_keyset_from_contract_state(&contract_state)?;
    fetch_and_store(mpc_p2p_client, keyshares_storage, &keyset).await
}

pub async fn fetch_and_store(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
    keyset: &contract_types::Keyset,
) -> anyhow::Result<()> {
    let keyshares = mpc_p2p_client
        .get_keyshares(keyset)
        .await
        .map_err(|err| anyhow::anyhow!("failed to get keyshares: {err:?}"))?;
    keyshares_storage
        .store_keyshares(&keyshares)
        .await
        .map_err(|err| anyhow::anyhow!("failed to store keyshares: {err:?}"))?;
    Ok(())
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
