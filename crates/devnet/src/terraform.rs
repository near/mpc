#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls

mod describe;

use crate::account::OperatingAccounts;
use crate::cli::{
    MpcDescribeCmd, MpcTerraformDeployInfraCmd, MpcTerraformDeployNomadCmd,
    MpcTerraformDestroyInfraCmd,
};
use crate::constants::DEFAULT_MPC_DOCKER_IMAGE;
use crate::devnet::OperatingDevnetSetup;
use crate::types::{MpcNetworkSetup, ParsedConfig};
use describe::TerraformInfraShowOutput;
use near_account_id::AccountId;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

// Get the sha256 hash of a docker image by pulling and inspecting it.
fn get_docker_image_hash(image: &str) -> anyhow::Result<String> {
    // Ensure the image is pulled first
    let pull = Command::new("docker").args(["pull", image]).output()?;
    if !pull.status.success() {
        anyhow::bail!(
            "Failed to pull docker image {}: {}",
            image,
            String::from_utf8_lossy(&pull.stderr)
        );
    }

    // Then inspect it
    let inspect = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", image])
        .output()?;
    if !inspect.status.success() {
        anyhow::bail!(
            "Failed to inspect docker image {}: {}",
            image,
            String::from_utf8_lossy(&inspect.stderr)
        );
    }

    let id = String::from_utf8(inspect.stdout)?.trim().to_string();
    Ok(id.strip_prefix("sha256:").unwrap_or(&id).to_string())
}

async fn export_terraform_infra_vars(name: &str, mpc_setup: &MpcNetworkSetup) -> PathBuf {
    let contract = mpc_setup
        .contract
        .clone()
        .expect("Contract is not deployed");
    let num_mpc_nodes = mpc_setup.participants.len();
    let terraform_file = TerraformDeployInfraFile {
        cluster_prefix: name.to_string(),
        num_mpc_nodes,
        mpc_contract_signer: contract,
        ssd: mpc_setup.ssd,
    };
    let terraform_file = serde_json::to_string_pretty(&terraform_file).unwrap();

    let current_dir = std::env::current_dir().unwrap();
    let path = current_dir.join(format!("mpc-{}.tfvars.json", name));
    std::fs::write(&path, terraform_file).unwrap();
    println!("Wrote terraform vars file at {}", path.display());
    path
}

/// Creates a {name}.tfvars.json file in the current directory with the Terraform variables
/// needed by the infra-ops scripts.
async fn export_terraform_vars(
    name: &str,
    accounts: &OperatingAccounts,
    mpc_setup: &MpcNetworkSetup,
    docker_image: Option<String>,
) -> PathBuf {
    let contract = mpc_setup
        .contract
        .clone()
        .expect("Contract is not deployed");
    let terraform_file = {
        let mut mpc_nodes = Vec::new();
        for (i, account_id) in mpc_setup.participants.iter().enumerate() {
            let responding_account_id = accounts
                .account(account_id)
                .get_mpc_participant()
                .unwrap()
                .responding_account_id
                .clone();
            mpc_nodes.push(TerraformMpcNode {
                account: account_id.clone(),
                url: format!("http://mpc-node-{}.service.mpc.consul:3000", i),
                number_of_responder_keys: mpc_setup.num_responding_access_keys,
                near_responder_account_id: responding_account_id,
            });
        }
        let docker_image = docker_image.as_deref().unwrap_or(DEFAULT_MPC_DOCKER_IMAGE);

        let image_hash =
            get_docker_image_hash(docker_image).expect("Failed to get docker image hash");

        let terraform_file = TerraformFile {
            cluster_prefix: name.to_string(),
            mpc_nodes,
            mpc_contract_signer: contract,
            ssd: mpc_setup.ssd,
            image_hash,
            latest_allowed_hash_file: "latest_hash.txt".to_string(),
        };
        serde_json::to_string_pretty(&terraform_file).unwrap()
    };

    let current_dir = std::env::current_dir().unwrap();
    let path = current_dir.join(format!("mpc-{}.tfvars.json", name));
    std::fs::write(&path, terraform_file).unwrap();
    println!("Wrote terraform vars file at {}", path.display());
    path
}

#[derive(Serialize)]
struct TerraformDeployInfraFile {
    cluster_prefix: String,
    num_mpc_nodes: usize,
    mpc_contract_signer: AccountId,
    ssd: bool,
}

#[derive(Serialize)]
struct TerraformFile {
    cluster_prefix: String,
    mpc_nodes: Vec<TerraformMpcNode>,
    mpc_contract_signer: AccountId,
    ssd: bool,
    image_hash: String,
    latest_allowed_hash_file: String,
}

#[derive(Serialize)]
struct TerraformMpcNode {
    account: AccountId,
    url: String,
    number_of_responder_keys: usize,
    near_responder_account_id: AccountId,
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
        let terraform_vars_file = export_terraform_infra_vars(name, mpc_setup).await;
        let infra_ops_path = &config.infra_ops_path;
        let infra_dir = infra_ops_path.join("provisioning/terraform/infra/mpc/base-mpc-cluster");

        // Make sure to init, and then create/select the workspace for this network.
        // Workspaces have independent state, so as long as the name is unique, this prevents any
        // conflict between networks.
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

        // If we need to reset keyshares, force replace the secrets.
        // We still need to run another apply afterwards because deleting the secrets
        // would also delete the IAM rules.
        if self.reset_keyshares {
            let mut command = std::process::Command::new("terraform");
            command
                .arg("apply")
                .arg("-var-file")
                .arg(&terraform_vars_file);
            for i in 0..mpc_setup.participants.len() {
                command.arg("-replace").arg(format!(
                    "google_secret_manager_secret.keyshare_secret[{}]",
                    i
                ));
            }
            command.current_dir(&infra_dir).print_and_run();
        }

        std::process::Command::new("terraform")
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .current_dir(&infra_dir)
            .print_and_run();

        // Query for the nomad server URL reported by Terraform. We store that for
        // deploy-nomad later.
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
        let terraform_vars_file =
            export_terraform_vars(name, &setup.accounts, mpc_setup, self.docker_image.clone())
                .await;
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

        let docker_image = self
            .docker_image
            .clone()
            .unwrap_or(DEFAULT_MPC_DOCKER_IMAGE.to_string());
        std::process::Command::new("terraform")
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .arg("-var")
            .arg(format!("shutdown_and_reset={}", self.shutdown_and_reset))
            .arg("-var")
            .arg(format!("docker_image={}", docker_image))
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();
    }
}

impl MpcTerraformDestroyInfraCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to destroy testing cluster infra with Terraform recipes located at {}",
            name,
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file = export_terraform_infra_vars(name, mpc_setup).await;
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
            .arg("destroy")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .current_dir(&infra_dir)
            .print_and_run();

        mpc_setup.nomad_server_url = None;
    }
}

pub fn get_urls(name: &str, config: &ParsedConfig) -> Vec<String> {
    let output: TerraformInfraShowOutput = get_terraform_values(name, config);
    let mut ret = Vec::new();
    for resource in &output.values.root_module.resources {
        if let Some((_, instance)) = resource.as_mpc_nomad_client() {
            ret.push(format!(
                "http://{}:8080",
                instance.nat_ip().unwrap_or_default()
            ));
            // todo: display account_ids on the endpoint too, as this index might not be reliable.
            // [(#712)](https://github.com/near/mpc/issues/712)
        }
    }
    ret
}

fn get_terraform_values(name: &str, config: &ParsedConfig) -> TerraformInfraShowOutput {
    let infra_ops_path = &config.infra_ops_path;
    let infra_dir = infra_ops_path.join("provisioning/terraform/infra/mpc/base-mpc-cluster");

    std::process::Command::new("terraform")
        .arg("init")
        .current_dir(&infra_dir)
        .output()
        .unwrap();

    std::process::Command::new("terraform")
        .arg("workspace")
        .arg("select")
        .arg("-or-create")
        .arg(name)
        .current_dir(&infra_dir)
        .output()
        .unwrap();

    let output = std::process::Command::new("terraform")
        .arg("show")
        .arg("-json")
        .current_dir(&infra_dir)
        .output()
        .expect("Failed to run terraform show -json");

    let output: TerraformInfraShowOutput =
        serde_json::from_slice(&output.stdout).expect("Failed to parse terraform show output");

    output
}

impl MpcDescribeCmd {
    pub async fn describe_terraform(&self, name: &str, config: &ParsedConfig) {
        let output: TerraformInfraShowOutput = get_terraform_values(name, config);
        for resource in &output.values.root_module.resources {
            if let Some(instance) = resource.as_mpc_nomad_server() {
                println!(
                    "Nomad server: http://{}",
                    instance.nat_ip().unwrap_or_default()
                );
            }
        }
        for resource in &output.values.root_module.resources {
            if let Some((index, instance)) = resource.as_mpc_nomad_client() {
                println!(
                    "Nomad client #{}: zone {}, instance type {}, debug: http://{}:8080/debug/tasks",
                    index,
                    instance.zone,
                    instance.machine_type,
                    instance.nat_ip().unwrap_or_default()
                );
            }
        }
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
