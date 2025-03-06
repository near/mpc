use crate::rpc::NearRpcClients;
use crate::types::Config;
use std::sync::Arc;

#[derive(clap::Parser)]
pub enum Cli {
    Mpc(MpcNetworkCmd),
    NewLoadtest(LoadtestCmd),
}

impl Cli {
    pub async fn run(self) {
        const CONFIG_FILE: &str = "config.yaml";
        let config = std::fs::read_to_string(CONFIG_FILE).unwrap();
        let config: Config = serde_yaml::from_str(&config).unwrap();
        let client = Arc::new(NearRpcClients::new(config.rpcs).await);

        match self {
            Cli::Mpc(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    MpcNetworkSubCmd::New(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::Update(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::TerraformExport(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::DeployContract(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::RemoveContract(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::ViewContract(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::Join(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    MpcNetworkSubCmd::VoteJoin(cmd) => {
                        cmd.run(&name, client).await;
                    }
                }
            }
            Cli::NewLoadtest(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    LoadtestSubCmd::New(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    LoadtestSubCmd::Update(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    LoadtestSubCmd::DeployParallelSignContract(cmd) => {
                        cmd.run(&name, client).await;
                    }
                    LoadtestSubCmd::Run(cmd) => {
                        cmd.run(&name, client).await;
                    }
                }
            }
        }
    }
}

#[derive(clap::Parser)]
pub struct MpcNetworkCmd {
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: MpcNetworkSubCmd,
}

#[derive(clap::Parser)]
pub enum MpcNetworkSubCmd {
    New(NewMpcNetworkCmd),
    Update(UpdateMpcNetworkCmd),
    TerraformExport(MpcTerraformExportCmd),
    DeployContract(MpcDeployContractCmd),
    RemoveContract(RemoveContractCmd),
    ViewContract(MpcViewContractCmd),
    Join(MpcJoinCmd),
    VoteJoin(MpcVoteJoinCmd),
}

#[derive(clap::Parser)]
pub struct LoadtestCmd {
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: LoadtestSubCmd,
}

#[derive(clap::Parser)]
pub enum LoadtestSubCmd {
    New(NewLoadtestCmd),
    Update(UpdateLoadtestCmd),
    DeployParallelSignContract(DeployParallelSignContractCmd),
    Run(RunLoadtestCmd),
}

#[derive(clap::Parser)]
pub struct NewMpcNetworkCmd {
    #[clap(long)]
    pub num_participants: usize,
    #[clap(long)]
    pub threshold: usize,
    #[clap(long, default_value = "1")]
    pub near_per_account: u128,
    // Number of additional access keys per participant to add for responding.
    // If non-zero, an additional account is created for each participant just for responding.
    #[clap(long)]
    pub num_responding_access_keys: usize,
    #[clap(long, default_value = "1")]
    pub near_per_responding_account: u128,
}

#[derive(clap::Parser)]
pub struct UpdateMpcNetworkCmd {
    #[clap(long)]
    pub num_participants: Option<usize>,
    #[clap(long)]
    pub threshold: Option<usize>,
    #[clap(long)]
    pub near_per_account: Option<u128>,
    #[clap(long)]
    pub num_responding_access_keys: Option<usize>,
    #[clap(long)]
    pub near_per_responding_account: Option<u128>,
}

#[derive(clap::Parser)]
pub struct MpcTerraformExportCmd {}

#[derive(clap::Parser)]
pub struct MpcDeployContractCmd {
    /// File path that contains the contract code.
    #[clap(long)]
    pub path: String,
    /// The number of participants to initialize with.
    #[clap(long)]
    pub init_participants: usize,
    #[clap(long, default_value = "9")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct RemoveContractCmd {}

#[derive(clap::Parser)]
pub struct MpcViewContractCmd {}

#[derive(clap::Parser)]
pub struct MpcJoinCmd {
    pub account_index: usize,
}

#[derive(clap::Parser)]
pub struct MpcVoteJoinCmd {
    pub for_account_index: usize,
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub struct NewLoadtestCmd {
    #[clap(long)]
    pub num_accounts: usize,
    #[clap(long)]
    pub keys_per_account: usize,
    #[clap(long)]
    pub near_per_account: u128,
}

#[derive(clap::Parser)]
pub struct UpdateLoadtestCmd {
    #[clap(long)]
    pub num_accounts: Option<usize>,
    #[clap(long)]
    pub keys_per_account: Option<usize>,
    #[clap(long)]
    pub near_per_account: Option<u128>,
}

#[derive(clap::Parser)]
pub struct DeployParallelSignContractCmd {
    /// File path that contains the parallel signature request contract code.
    #[clap(long)]
    pub path: String,
    #[clap(long, default_value = "1")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct RunLoadtestCmd {
    #[clap(long)]
    pub mpc_network: String,
    #[clap(long)]
    pub qps: usize,
    #[clap(long)]
    pub signatures_per_contract_call: Option<usize>,
}
