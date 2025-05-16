use std::{collections::BTreeMap, time::Duration};

use crate::{
    cli::{
        MpcDeployContractCmd, MpcTerraformDeployInfraCmd, MpcTerraformDeployNomadCmd,
        MpcVoteAddDomainsCmd, NewLoadtestCmd, NewMpcNetworkCmd, RunLoadtestCmd,
        SimpleClusterTestCmd,
    },
    devnet::OperatingDevnetSetup,
    mpc::domains_ready,
    types::load_config,
};

impl SimpleClusterTestCmd {
    pub async fn run(&self) {
        let config = load_config().await;
        NewMpcNetworkCmd {
            num_participants: self.num_participants,
            near_per_account: 1,
            num_responding_access_keys: 5,
            near_per_responding_account: 8,
            ssd: true,
        }
        .run(&self.name, config.clone())
        .await;

        MpcDeployContractCmd {
            path: self.contract_path.clone(),
            init_participants: self.num_participants,
            threshold: self.threshold,
            deposit_near: 20,
        }
        .run(&self.name, config.clone())
        .await;

        let mpc_setup = MpcTerraformDeployInfraCmd {
            reset_keyshares: false,
        }
        .run(&self.name, config.clone())
        .await;

        while !mpc_setup.nomad_is_ready().await {
            println!("waiting for nomad");
            tokio::time::sleep(Duration::from_secs(30)).await;
        }

        println!("deploying docker images");
        // wait for infra to be deployed
        // query the endpoint?
        let mut docker_images = BTreeMap::new();
        if let Some(image) = &self.docker_image_start {
            docker_images.insert(image.to_string(), vec![]);
        }

        let cluster = MpcTerraformDeployNomadCmd {
            shutdown_and_reset: false,
            reset_node_index: None,
            docker_images: Some(docker_images),
        }
        .run(&self.name, config.clone())
        .await;

        while !cluster.cluster_is_ready().await {
            println!("\n Cluster not ready, waiting 2 minutes.");
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
        println!("Cluster is ready");

        println!("Voting to add domains");
        MpcVoteAddDomainsCmd {
            signature_schemes: vec!["Secp256k1".to_string(), "Ed25519".to_string()],
            voters: vec![],
        }
        .run(&self.name, config.clone())
        .await;
        println!("Creating new loadtest");
        let loadtest_name = format!("{}-test", self.name);
        NewLoadtestCmd {
            num_accounts: 1,
            keys_per_account: 8,
            near_per_account: 10,
        }
        .run(&loadtest_name, config.clone())
        .await;

        let contract = mpc_setup
            .contract
            .clone()
            .expect("MPC network does not have a contract");

        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        while !domains_ready(&setup.accounts, &contract, &[0, 1]).await {
            println!("Waiting for domains");
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
        println!("Running loadtest for domain 0");
        RunLoadtestCmd {
            mpc_network: self.name.clone(),
            qps: 5,
            signatures_per_contract_call: None,
            domain_id: Some(0),
            duration: Some(60),
        }
        .run(&loadtest_name, config.clone())
        .await;
        println!("Running loadtest for domain 1");
        RunLoadtestCmd {
            mpc_network: self.name.clone(),
            qps: 5,
            signatures_per_contract_call: None,
            domain_id: Some(1),
            duration: Some(60),
        }
        .run(&loadtest_name, config.clone())
        .await;
    }
}
