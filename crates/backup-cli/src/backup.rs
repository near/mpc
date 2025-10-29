use contract_interface::types as contract_types;
use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use std::{path::PathBuf, str::FromStr};
use tokio::fs::File;

use crate::{
    adapters::{self, contract_state_fixture::get_keyset_from_contract_state, near_contract},
    cli,
    ports::{self, SecretsRepository},
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
            let secrets = secrets_storage
                .load_secrets()
                .await
                .expect("fail to load secrets");
            let mpc_contract = near_contract::NearContractAdapter::new(
                command_args.mpc_contract_account_id,
                command_args.near_network,
                command_args.signer_account_id,
                secrets.near_signer_key,
            );
            register_backup_service(&secrets_storage, &mpc_contract).await;
        }
        cli::Command::GetKeyshares(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");
            let p2p_private_key = ports::SecretsRepository::load_secrets(&secrets_storage)
                .await
                .expect("fail to load secrets")
                .p2p_private_key;
            let mpc_node_p2p_key = verifying_key_from_str(&subcommand_args.mpc_node_p2p_key);
            let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
                subcommand_args.mpc_node_url,
                mpc_node_p2p_key,
                p2p_private_key,
            );
            let key_shares_storage = adapters::DummyKeyshareStorage {};
            let mpc_contract =
                adapters::contract_state_fixture::ContractStateFixture::new(home_dir);
            get_keyshares(&mpc_p2p_client, &key_shares_storage, &mpc_contract).await;
        }
        cli::Command::PutKeyshares(subcommand_args) => {
            let home_dir = PathBuf::from(args.home_dir);
            let secrets_storage =
                adapters::secrets_storage::SharedJsonSecretsStorage::<File>::open_read(
                    home_dir.as_path(),
                )
                .await
                .expect("failed to create secrets storage");
            let p2p_private_key = ports::SecretsRepository::load_secrets(&secrets_storage)
                .await
                .expect("fail to load secrets")
                .p2p_private_key;
            let mpc_node_p2p_key = verifying_key_from_str(&subcommand_args.mpc_node_p2p_key);
            let mpc_p2p_client = adapters::p2p_client::MpcP2PClient::new(
                subcommand_args.mpc_node_url,
                mpc_node_p2p_key,
                p2p_private_key,
            );
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

pub async fn register_backup_service(
    secrets_storage: &impl ports::SecretsRepository,
    mpc_contract: &impl ports::RegisterBackupData,
) {
    let secrets = secrets_storage
        .load_secrets()
        .await
        .expect("fail to load secrets");

    mpc_contract
        .register_backup_data(&secrets.p2p_private_key.verifying_key())
        .await
        .expect("failed to register backup data");
}

pub async fn get_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
    mpc_contract: &impl ports::ContractStateReader,
) {
    let contract_state = mpc_contract
        .get_contract_state()
        .await
        .expect("could not get contract state");
    let keyset =
        get_keyset_from_contract_state(&contract_state).expect("failed to compute current keyset");
    let keyshare = mpc_p2p_client
        .get_keyshares(&keyset)
        .await
        .expect("fail to get key shares");
    keyshares_storage
        .store_keyshares(&keyshare)
        .await
        .expect("fail to store key shares");
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
