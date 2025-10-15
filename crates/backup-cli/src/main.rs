use backup_cli::{backup::BackupService, cli};
use clap::Parser as _;
use backup_cli::adapters;

fn main() {

    let args = cli::Args::parse();
    let secret_storage = adapters::DummySecretsStorage {};
    let key_shares_storage = adapters::DummyKeyshareStorage {};
    let mpc_p2p_client = adapters::DummyP2PClient {};
    let mpc_contract = adapters::DummyContractInterface {};
    let backup_service: BackupService<adapters::DummySecretsStorage, adapters::DummyKeyshareStorage, adapters::DummyP2PClient, _> = BackupService::new(secret_storage, key_shares_storage, mpc_p2p_client, mpc_contract);
}
