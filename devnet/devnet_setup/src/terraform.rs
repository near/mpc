use crate::cli::MpcTerraformExportCmd;
use crate::devnet::OperatingDevnetSetup;
use crate::rpc::NearRpcClients;
use near_crypto::{PublicKey, SecretKey};
use near_sdk::AccountId;
use serde::Serialize;
use std::sync::Arc;

impl MpcTerraformExportCmd {
    pub async fn run(&self, name: &str, rpc: Arc<NearRpcClients>) {
        println!(
            "Going to export Terraform configuration for MPC network {}",
            name
        );
        let setup = OperatingDevnetSetup::load(rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let mut mpc_nodes = Vec::new();
        for (i, account_id) in mpc_setup.participants.iter().enumerate() {
            let account = setup.accounts.account(account_id);
            let participant = account
                .get_mpc_participant()
                .expect("Not an MPC participant");
            let responding_account = setup.accounts.account(&participant.responding_account_id);
            let respond_config = RespondConfigFile {
                account_id: participant.responding_account_id.clone(),
                access_keys: responding_account
                    .all_access_keys()
                    .await
                    .into_iter()
                    .map(|k| k.secret_key())
                    .collect(),
            };
            let mpc_node = TerraformMpcNode {
                account: account_id.clone(),
                account_pk: account.any_access_key().await.secret_key().public_key(),
                account_sk: account.any_access_key().await.secret_key().clone(),
                sign_sk: participant.p2p_private_key.clone(),
                url: format!("http://mpc-node-{}.service.mpc.consul:3000", i),
                respond_yaml: serde_yaml::to_string(&respond_config).unwrap(),
            };
            mpc_nodes.push(mpc_node);
        }
        let terraform_file = TerraformFile {
            mpc_nodes,
            mpc_contract_signer: contract,
        };
        let terraform_file = serde_json::to_string_pretty(&terraform_file).unwrap();
        std::fs::write(format!("mpc-{}.tfvars.json", name), terraform_file).unwrap();
    }
}

#[derive(Serialize)]
struct TerraformFile {
    mpc_nodes: Vec<TerraformMpcNode>,
    mpc_contract_signer: AccountId,
}

#[derive(Serialize)]
struct TerraformMpcNode {
    account: AccountId,
    account_pk: PublicKey,
    account_sk: SecretKey,
    sign_sk: SecretKey,
    url: String,
    respond_yaml: String,
}

// From MPC code.
#[derive(Serialize)]
pub struct RespondConfigFile {
    pub account_id: AccountId,
    pub access_keys: Vec<SecretKey>,
}
