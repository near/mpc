use contract_interface::types as contract_types;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::node_migrations::BackupServiceInfo;
use rand_core::OsRng;
use std::{path::PathBuf, str::FromStr};
use tokio::fs::File;

use crate::{
    adapters::{self, contract_interface::get_keyset_from_contract_state},
    cli::{self, Network},
    ports,
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
            let secrets = ports::SecretsRepository::load_secrets(&secrets_storage)
                .await
                .expect("fail to load secrets");
            register_backup_service(
                &command_args.mpc_contract_name,
                &command_args.near_network,
                secrets.p2p_private_key.verifying_key(),
                &secrets.near_signer_key,
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
            let mpc_contract = adapters::contract_interface::ContractStateFixture::new(home_dir);
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
    contract_account_id: &str,
    network: &Network,
    p2p_public_key: VerifyingKey,
    signer_key: &SigningKey,
) {
    let backup_service_info = BackupServiceInfo {
        public_key: contract_types::Ed25519PublicKey::from(*p2p_public_key.as_bytes()),
    };

    let signer = {
        let secret_key_b58 = bs58::encode(signer_key.to_bytes()).into_string();
        near_workspaces::types::SecretKey::from_str(&format!("ed25519:{}", secret_key_b58))
            .expect("Failed to create secret key")
    };

    let account_id_hex = hex::encode(signer_key.verifying_key().as_bytes());
    let signer_account_id = account_id_hex.parse().expect("Invalid signer account ID");

    macro_rules! connect_and_call {
        ($network:expr) => {
            call_register_on_network(
                $network.await.expect("Failed to connect to NEAR network"),
                signer_account_id,
                signer,
                contract_account_id,
                backup_service_info,
            )
            .await
        };
    }

    match network {
        Network::Testnet => connect_and_call!(near_workspaces::testnet()),
        Network::Mainnet => connect_and_call!(near_workspaces::mainnet()),
        Network::Sandbox => connect_and_call!(near_workspaces::sandbox()),
    }
}

async fn call_register_on_network<T: near_workspaces::Network + 'static>(
    worker: near_workspaces::Worker<T>,
    signer_account_id: near_workspaces::types::AccountId,
    signer: near_workspaces::types::SecretKey,
    contract_account_id: &str,
    backup_service_info: BackupServiceInfo,
) {
    let account = near_workspaces::Account::from_secret_key(signer_account_id, signer, &worker);
    account
        .call(
            &contract_account_id
                .parse()
                .expect("Invalid contract account ID"),
            "register_backup_service",
        )
        .args_json(serde_json::json!({
            "backup_service_info": backup_service_info,
        }))
        .max_gas()
        .transact()
        .await
        .expect("fail to register backup data")
        .into_result()
        .expect("transaction execution failed");
}

pub async fn get_keyshares(
    mpc_p2p_client: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
    mpc_contract: &impl ports::ContractInterface,
) {
    let contract_state = mpc_contract
        .get_contract_state()
        .await
        .expect("Could not get contract state");
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
        .expect("Invalid mpc_node_p2p_key value");
    VerifyingKey::from_bytes(mpc_node_p2p_key.as_bytes()).expect("Invalid mpc_node_p2p_key value")
}
