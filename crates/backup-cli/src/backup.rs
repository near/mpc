use crate::adapters;
use crate::cli;
use crate::ports;

pub async fn run_command(args: cli::Args) {
    match args.command {
        cli::Command::GenerateKeys(_args) => {
            let secrets_storage = adapters::DummySecretsStorage {};
            generate_keypair(&secrets_storage).await;
        }
        cli::Command::Register(_args) => {
            let secrets_storage = adapters::DummySecretsStorage {};
            let mpc_contract = adapters::DummyContractInterface {};
            register_backup_service(&secrets_storage, &mpc_contract).await;
        }
        cli::Command::GetKeyshares(_args) => {
            let mpc_p2p_client = adapters::DummyP2PClient {};
            let key_shares_storage = adapters::DummyKeyshareStorage {};
            get_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
        cli::Command::PutKeyshares(_args) => {
            let mpc_p2p_client = adapters::DummyP2PClient {};
            let key_shares_storage = adapters::DummyKeyshareStorage {};
            put_keyshares(&mpc_p2p_client, &key_shares_storage).await;
        }
    }
}

pub async fn generate_keypair(secrets_storage: &impl ports::SecretsRepository) {
    let private_key = crate::types::PrivateKey {};
    secrets_storage
        .store_private_key(&private_key)
        .await
        .expect("fail to store private key");
}

/// Put backup service data to the smart contract
pub async fn register_backup_service(
    secrets_storage: &impl ports::SecretsRepository,
    mpc_contract: &impl ports::ContractInterface,
) {
    let public_key = secrets_storage
        .load_private_key()
        .await
        .expect("fail to load private key")
        .public_key();
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
