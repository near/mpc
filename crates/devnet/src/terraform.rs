#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls

mod describe;

use crate::account::OperatingAccounts;
use crate::cli::{
    MpcDescribeCmd, MpcTerraformDeployChainCmd, MpcTerraformDeployInfraCmd,
    MpcTerraformDeployNomadCmd, MpcTerraformDestroyInfraCmd,
};
use crate::constants::{
    DEFAULT_MPC_DOCKER_IMAGE, LOCALNET_ASSETS_DIR, LOCALNET_CHAIN_ID, LOCALNET_PLACEHOLDER_CONTRACT,
};
use crate::devnet::OperatingDevnetSetup;
use crate::types::{MpcNetworkSetup, ParsedConfig};
use describe::TerraformInfraShowOutput;
use near_account_id::AccountId;
use serde::Serialize;
use std::path::{Path, PathBuf};
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

/// The contract signer to pass to terraform. On localnet the cluster + validator are brought up
/// before the contract is deployed, so a placeholder is used until then; on testnet a deployed
/// contract is required.
fn resolve_contract_signer(mpc_setup: &MpcNetworkSetup, chain_id: &str) -> AccountId {
    match mpc_setup.contract.clone() {
        Some(contract) => contract,
        None if chain_id == LOCALNET_CHAIN_ID => LOCALNET_PLACEHOLDER_CONTRACT.parse().unwrap(),
        None => panic!("Contract is not deployed"),
    }
}

async fn export_terraform_infra_vars(
    name: &str,
    mpc_setup: &MpcNetworkSetup,
    chain_id: &str,
) -> PathBuf {
    let contract = resolve_contract_signer(mpc_setup, chain_id);
    // Size from the intended count so the cluster can be provisioned before participants are funded
    // (localnet funds after the chain is up).
    let num_mpc_nodes = mpc_setup
        .participants
        .len()
        .max(mpc_setup.desired_num_participants);
    let terraform_file = TerraformDeployInfraFile {
        cluster_prefix: name.to_string(),
        num_mpc_nodes,
        mpc_contract_signer: contract,
        ssd: mpc_setup.ssd,
        chain_id: chain_id.to_string(),
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
    chain_id: &str,
) -> PathBuf {
    let contract = resolve_contract_signer(mpc_setup, chain_id);
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

        // On localnet, hand infra-ops the static chain assets so it can run a stock neard validator
        // (delivered via Nomad templates) without baking a custom image or copying files into the
        // infra repo. Empty on testnet.
        let neard = if chain_id == LOCALNET_CHAIN_ID {
            NeardAssets::load()
        } else {
            NeardAssets::default()
        };
        let terraform_file = TerraformFile {
            cluster_prefix: name.to_string(),
            mpc_nodes,
            mpc_contract_signer: contract,
            image_hash,
            latest_allowed_hash_file: "latest_hash.txt".to_string(),
            chain_id: chain_id.to_string(),
            neard_genesis: neard.genesis,
            neard_config: neard.config,
            neard_node_key: neard.node_key,
            neard_validator_key: neard.validator_key,
        };
        serde_json::to_string_pretty(&terraform_file).unwrap()
    };

    let current_dir = std::env::current_dir().unwrap();
    let path = current_dir.join(format!("mpc-{}.tfvars.json", name));
    std::fs::write(&path, terraform_file).unwrap();
    println!("Wrote terraform vars file at {}", path.display());
    path
}

/// Writes a tfvars file for bringing up only the localnet validator (no MPC node jobs), used by
/// `deploy-chain` before any participants are funded or the contract is deployed. It carries the
/// neard chain assets and leaves the MPC-only fields as harmless placeholders (no MPC jobs run).
async fn export_terraform_chain_vars(name: &str) -> PathBuf {
    let neard = NeardAssets::load();
    let terraform_file = TerraformFile {
        cluster_prefix: name.to_string(),
        mpc_nodes: Vec::new(),
        mpc_contract_signer: LOCALNET_PLACEHOLDER_CONTRACT.parse().unwrap(),
        image_hash: String::new(),
        latest_allowed_hash_file: "latest_hash.txt".to_string(),
        chain_id: LOCALNET_CHAIN_ID.to_string(),
        neard_genesis: neard.genesis,
        neard_config: neard.config,
        neard_node_key: neard.node_key,
        neard_validator_key: neard.validator_key,
    };
    let terraform_file = serde_json::to_string_pretty(&terraform_file).unwrap();

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
    /// Chain the cluster runs against (`testnet` or `mpc-localnet`); drives the localnet validator.
    chain_id: String,
}

#[derive(Serialize)]
struct TerraformFile {
    cluster_prefix: String,
    mpc_nodes: Vec<TerraformMpcNode>,
    mpc_contract_signer: AccountId,
    image_hash: String,
    latest_allowed_hash_file: String,
    /// Chain the nodes run against (`testnet` or `mpc-localnet`); selects boot nodes / genesis.
    chain_id: String,
    /// Localnet chain assets, delivered to a stock neard validator via Nomad templates. All empty
    /// on testnet. infra-ops derives the boot-node public key from `neard_node_key`.
    neard_genesis: String,
    neard_config: String,
    neard_node_key: String,
    neard_validator_key: String,
}

/// The static localnet chain assets the neard validator needs, read from [`LOCALNET_ASSETS_DIR`].
#[derive(Default)]
struct NeardAssets {
    genesis: String,
    /// `config.json` with the RPC/network binds rewritten to `0.0.0.0` (the checked-in file binds to
    /// localhost for single-host use), so MPC nodes on other machines can peer and RPC.
    config: String,
    node_key: String,
    validator_key: String,
}

impl NeardAssets {
    fn load() -> Self {
        let dir = Path::new(LOCALNET_ASSETS_DIR);
        Self {
            genesis: read_asset(&dir.join("genesis.json")),
            config: rebind_neard_config(&read_asset(&dir.join("config.json"))),
            node_key: read_asset(&dir.join("node_key.json")),
            validator_key: read_asset(&dir.join("validator_key.json")),
        }
    }
}

fn read_asset(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("localnet asset should exist at {}: {e}", path.display()))
}

/// Rewrites the RPC and network listen addresses in a neard `config.json` to bind all interfaces.
fn rebind_neard_config(config: &str) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(config).expect("localnet config.json should be valid JSON");
    for (section, addr) in [("rpc", "0.0.0.0:3030"), ("network", "0.0.0.0:24566")] {
        let section = value
            .get_mut(section)
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| panic!("localnet config.json should have a `{section}` object"));
        section.insert("addr".to_string(), serde_json::json!(addr));
    }
    serde_json::to_string_pretty(&value).unwrap()
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
        let is_localnet = config.is_localnet();
        let mut setup = OperatingDevnetSetup::load_offline(config.rpc);
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file =
            export_terraform_infra_vars(name, mpc_setup, &config.chain_id).await;
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

        // On localnet, surface the validator's RPC URL so the operator can point config.yaml at it.
        if is_localnet {
            let neard_rpc_url = std::process::Command::new("terraform")
                .arg("output")
                .arg("-raw")
                .arg("neard_rpc_url")
                .current_dir(&infra_dir)
                .output()
                .expect("Failed to run terraform output -raw neard_rpc_url");
            let neard_rpc_url = String::from_utf8(neard_rpc_url.stdout).unwrap();
            println!(
                "\nLocalnet validator RPC: {}\n\
                 Set this as the `rpcs` url in config.yaml, then run `deploy-chain` to start the \
                 validator.",
                neard_rpc_url
            );
        }
    }
}

impl MpcTerraformDeployNomadCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to deploy testing cluster Nomad jobs with Terraform recipes located at {}",
            name,
        );
        let setup = OperatingDevnetSetup::load_offline(config.rpc);
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file = export_terraform_vars(
            name,
            &setup.accounts,
            mpc_setup,
            self.docker_image.clone(),
            &config.chain_id,
        )
        .await;
        let nomad_server_url = mpc_setup
            .nomad_server_url
            .clone()
            .expect("Nomad server URL is not set; is the infra deployed?");
        // Default the validator image to the one recorded by deploy-chain, so it need not be
        // repeated here (and can't accidentally diverge).
        let neard_docker_image = self
            .neard_docker_image
            .clone()
            .or_else(|| mpc_setup.neard_docker_image.clone());

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
        let mut command = std::process::Command::new("terraform");
        command
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .arg("-var")
            .arg(format!("shutdown_and_reset={}", self.shutdown_and_reset))
            .arg("-var")
            .arg(format!("docker_image={}", docker_image));
        // The neard validator job only exists on localnet; never deploy it (or pass its image)
        // otherwise. On localnet this apply also reconciles it, so it needs the validator image —
        // taken from --neard-docker-image or the value recorded by deploy-chain.
        if config.chain_id == LOCALNET_CHAIN_ID {
            let neard_docker_image = neard_docker_image.expect(
                "no neard image found: run deploy-chain first, or pass --neard-docker-image",
            );
            command
                .arg("-var")
                .arg(format!("neard_docker_image={}", neard_docker_image));
        }
        command
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();
    }
}

impl MpcTerraformDeployChainCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        assert!(
            config.is_localnet(),
            "deploy-chain only applies to localnet (set chain_id: mpc-localnet in config.yaml)"
        );
        println!(
            "Going to deploy the localnet validator (neard) for {}",
            name
        );
        let mut setup = OperatingDevnetSetup::load_offline(config.rpc);
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let nomad_server_url = mpc_setup
            .nomad_server_url
            .clone()
            .expect("Nomad server URL is not set; run deploy-infra first");

        let terraform_vars_file = export_terraform_chain_vars(name).await;
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

        // deploy-chain applies with an empty `mpc_nodes` list, so if the MPC node jobs are already
        // deployed in this workspace (deploy-nomad has run), re-running it here would tear them
        // down. Refuse in that case; the validator should be updated via deploy-nomad instead.
        let state = std::process::Command::new("terraform")
            .arg("state")
            .arg("list")
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .output()
            .expect("Failed to run terraform state list");
        let state = String::from_utf8(state.stdout).unwrap();
        if state
            .lines()
            .any(|resource| resource.starts_with("nomad_job.mpc_node["))
        {
            panic!(
                "MPC node jobs are already deployed; re-running deploy-chain would tear them down. \
                 Use `deploy-nomad --neard-docker-image <tag>` to update the validator instead."
            );
        }

        // The chain vars carry an empty `mpc_nodes` list, so the MPC node job count resolves to 0
        // and a normal apply brings up just the neard validator (plus base monitoring) — no MPC
        // node jobs, and no need for `-target`. This works before the contract is deployed.
        std::process::Command::new("terraform")
            .arg("apply")
            .arg("-var-file")
            .arg(terraform_vars_file)
            .arg("-var")
            .arg(format!("neard_docker_image={}", self.neard_docker_image))
            .current_dir(&infra_dir)
            .env("NOMAD_ADDR", &nomad_server_url)
            .print_and_run();

        // Record the image only after a successful apply (terraform failure exits before here, and
        // the re-run guard panics before here), so deploy-nomad reuses exactly what was deployed.
        setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name))
            .neard_docker_image = Some(self.neard_docker_image.clone());
    }
}

impl MpcTerraformDestroyInfraCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to destroy testing cluster infra with Terraform recipes located at {}",
            name,
        );
        let mut setup = OperatingDevnetSetup::load_offline(config.rpc);
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let terraform_vars_file =
            export_terraform_infra_vars(name, mpc_setup, &config.chain_id).await;
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
            // TODO(#712): display account_ids on the endpoint too, as this index might not be reliable
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn terraform_file__should_serialize_localnet_chain_id() {
        // Given
        let terraform_file = TerraformFile {
            cluster_prefix: "bench".to_string(),
            mpc_nodes: Vec::new(),
            mpc_contract_signer: "contract.test.near".parse().unwrap(),
            image_hash: "abc".to_string(),
            latest_allowed_hash_file: "latest_hash.txt".to_string(),
            chain_id: "mpc-localnet".to_string(),
            neard_genesis: "{}".to_string(),
            neard_config: "{}".to_string(),
            neard_node_key: "{}".to_string(),
            neard_validator_key: "{}".to_string(),
        };

        // When
        let value = serde_json::to_value(&terraform_file).unwrap();

        // Then
        assert_eq!(value["chain_id"], "mpc-localnet");
    }

    #[test]
    fn resolve_contract_signer__should_use_placeholder_on_localnet_before_deploy() {
        // Given
        let mpc_setup = MpcNetworkSetup::default();

        // When
        let signer = resolve_contract_signer(&mpc_setup, "mpc-localnet");

        // Then
        assert_eq!(signer.as_str(), "placeholder.test.near");
    }

    #[test]
    fn resolve_contract_signer__should_use_deployed_contract_when_present() {
        // Given
        let mpc_setup = MpcNetworkSetup {
            contract: Some("real.test.near".parse().unwrap()),
            ..Default::default()
        };

        // When
        let signer = resolve_contract_signer(&mpc_setup, "mpc-localnet");

        // Then
        assert_eq!(signer.as_str(), "real.test.near");
    }

    #[test]
    #[should_panic(expected = "Contract is not deployed")]
    fn resolve_contract_signer__should_panic_on_testnet_without_contract() {
        // Given
        let mpc_setup = MpcNetworkSetup::default();

        // When / Then
        resolve_contract_signer(&mpc_setup, "testnet");
    }

    #[test]
    fn rebind_neard_config__should_bind_all_interfaces() {
        // Given
        let config = r#"{"rpc":{"addr":"127.0.0.1:3030"},"network":{"addr":"127.0.0.1:24566"}}"#;

        // When
        let rebound: serde_json::Value =
            serde_json::from_str(&rebind_neard_config(config)).unwrap();

        // Then
        assert_eq!(rebound["rpc"]["addr"], "0.0.0.0:3030");
        assert_eq!(rebound["network"]["addr"], "0.0.0.0:24566");
    }

    #[test]
    fn terraform_infra_file__should_serialize_chain_id() {
        // Given
        let terraform_file = TerraformDeployInfraFile {
            cluster_prefix: "bench".to_string(),
            num_mpc_nodes: 2,
            mpc_contract_signer: "contract.test.near".parse().unwrap(),
            ssd: false,
            chain_id: "testnet".to_string(),
        };

        // When
        let value = serde_json::to_value(&terraform_file).unwrap();

        // Then
        assert_eq!(value["chain_id"], "testnet");
    }
}
