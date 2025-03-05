use crate::account::OperatingAccounts;
use crate::cli::{MpcTerraformDeployInfraCmd, MpcTerraformDeployNomadCmd};
use crate::devnet::OperatingDevnetSetup;
use crate::types::{MpcNetworkSetup, ParsedConfig};
use near_crypto::{PublicKey, SecretKey};
use near_sdk::AccountId;
use serde::Serialize;
use std::path::PathBuf;

async fn export_terraform_vars(
    name: &str,
    accounts: &OperatingAccounts,
    mpc_setup: &MpcNetworkSetup,
) -> PathBuf {
    let contract = mpc_setup
        .contract
        .clone()
        .expect("Contract is not deployed");
    let mut mpc_nodes = Vec::new();
    for (i, account_id) in mpc_setup.participants.iter().enumerate() {
        let account = accounts.account(account_id);
        let participant = account
            .get_mpc_participant()
            .expect("Not an MPC participant");
        let responding_account = accounts.account(&participant.responding_account_id);
        let respond_config = RespondConfigFile {
            account_id: participant.responding_account_id.clone(),
            access_keys: responding_account
                .all_access_keys()
                .await
                .into_iter()
                .map(|k| k.secret_key())
                .collect(),
        };
        let account_sk = account.any_access_key().await.secret_key();
        let mpc_node = TerraformMpcNode {
            account: account_id.clone(),
            account_pk: account_sk.public_key(),
            account_sk,
            sign_sk: participant.p2p_private_key.clone(),
            sign_pk: participant.p2p_private_key.public_key(),
            url: format!("http://mpc-node-{}.service.mpc.consul:3000", i),
            respond_yaml: serde_yaml::to_string(&respond_config).unwrap(),
        };
        mpc_nodes.push(mpc_node);
    }
    let terraform_file = TerraformFile {
        cluster_prefix: name.to_string(),
        mpc_nodes,
        mpc_contract_signer: contract,
    };
    let terraform_file = serde_json::to_string_pretty(&terraform_file).unwrap();
    let current_dir = std::env::current_dir().unwrap();
    let path = current_dir.join(format!("mpc-{}.tfvars.json", name));
    std::fs::write(&path, terraform_file).unwrap();
    println!("Wrote terraform vars file at {}", path.display());
    path
}

#[derive(Serialize)]
struct TerraformFile {
    cluster_prefix: String,
    mpc_nodes: Vec<TerraformMpcNode>,
    mpc_contract_signer: AccountId,
}

#[derive(Serialize)]
struct TerraformMpcNode {
    account: AccountId,
    account_pk: PublicKey,
    account_sk: SecretKey,
    sign_sk: SecretKey,
    sign_pk: PublicKey,
    url: String,
    respond_yaml: String,
}

// From MPC code.
#[derive(Serialize)]
pub struct RespondConfigFile {
    pub account_id: AccountId,
    pub access_keys: Vec<SecretKey>,
}

impl MpcTerraformDeployInfraCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to deploy testing cluster infra with Terraform recipes located at {}",
            name,
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file = export_terraform_vars(name, &setup.accounts, mpc_setup).await;
        // Invoke terraform
        let infra_ops_path = &config.infra_ops_path;
        let infra_dir = infra_ops_path.join("provisioning/terraform/infra/mpc/base-mpc-cluster");

        std::process::Command::new("terraform")
            .arg("init")
            .current_dir(&infra_dir)
            .print_and_run();

        std::process::Command::new("terraform")
            .arg("workspace")
            .arg("select")
            .arg("-or-create")
            .arg(name)
            .current_dir(&infra_dir)
            .print_and_run();

        std::process::Command::new("terraform")
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .current_dir(&infra_dir)
            .print_and_run();

        let nomad_server_url = std::process::Command::new("terraform")
            .arg("output")
            .arg("-raw")
            .arg("nomad_server_ui")
            .current_dir(&infra_dir)
            .output()
            .expect("Failed to run terraform output -raw nomad_server_ui");
        let nomad_server_url = String::from_utf8(nomad_server_url.stdout).unwrap();
        mpc_setup.nomad_server_url = Some(nomad_server_url);
    }
}

impl MpcTerraformDeployNomadCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to deploy testing cluster Nomad jobs with Terraform recipes located at {}",
            name,
        );
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file = export_terraform_vars(name, &setup.accounts, mpc_setup).await;
        let nomad_server_url = mpc_setup
            .nomad_server_url
            .clone()
            .expect("Nomad server URL is not set; is the infra deployed?");

        // Invoke terraform
        let infra_ops_path = &config.infra_ops_path;
        let infra_dir = infra_ops_path.join("provisioning/nomad/base-mpc");

        std::process::Command::new("terraform")
            .arg("init")
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();

        std::process::Command::new("terraform")
            .arg("workspace")
            .arg("select")
            .arg("-or-create")
            .arg(name)
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();

        std::process::Command::new("terraform")
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();
    }
}

trait CommandExt {
    fn print_and_run(&mut self);
}

impl CommandExt for std::process::Command {
    fn print_and_run(&mut self) {
        println!("Running command: {:?}", self);
        let status = self.status().expect("Failed to execute command");
        if !status.success() {
            panic!(
                "Command failed with exit code {}: {:?}",
                status.code().unwrap(),
                self
            );
        }
    }
}
