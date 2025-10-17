use rand_core::OsRng;
use std::path::PathBuf;
use tokio::fs::File;

use crate::adapters;
use crate::cli;
use crate::ports;
use crate::types::PersistentSecrets;

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
        cli::Command::Register(_command_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");
            let mpc_contract = adapters::DummyContractInterface {};
            register_backup_service(&secrets_storage, &mpc_contract).await;
        }
        cli::Command::GetKeyshares(subcommand_args) => {
            let mpc_p2p_client = adapters::MpcP2PClient::new(subcommand_args.mpc_node_url, subcommand_args.mpc_node_p2p_key);
            let key_shares_storage = adapters::DummyKeyshareStorage {};
            get_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
        cli::Command::PutKeyshares(subcommand_args) => {
            let mpc_p2p_client = adapters::MpcP2PClient::new(subcommand_args.mpc_node_url, subcommand_args.mpc_node_p2p_key);
            let key_shares_storage = adapters::DummyKeyshareStorage {};
            put_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
    }
}

pub async fn generate_secrets(secrets_storage: &impl ports::SecretsRepository) {
    let persistent_secrets = PersistentSecrets::generate(&mut OsRng);
    secrets_storage
        .store_secrets(&persistent_secrets)
        .await
        .expect("fail to store private key");
}

/// Put backup service data to the smart contract
pub async fn register_backup_service(
    secrets_storage: &impl ports::SecretsRepository,
    mpc_contract: &impl ports::ContractInterface,
) {
    let secrets = secrets_storage
        .load_secrets()
        .await
        .expect("fail to load private key");
    let public_key = secrets.p2p_private_key.verifying_key();
    mpc_contract
        .register_backup_data(&public_key)
        .await
        .expect("fail to register backup data");
}

pub async fn get_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    key_shares_storage: &impl ports::KeyShareRepository,
) {
    let keyshare = mpc_p2p_client
        .get_key_shares()
        .await
        .expect("fail to get key shares");
    key_shares_storage
        .store_key_shares(&keyshare)
        .await
        .expect("fail to store key shares");
}

pub async fn put_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    key_shares_storage: &impl ports::KeyShareRepository,
) {
    let key_shares = key_shares_storage
        .load_key_shares()
        .await
        .expect("fail to load key shares");
    mpc_p2p_client
        .put_key_shares(&key_shares)
        .await
        .expect("fail to put key shares");
}
