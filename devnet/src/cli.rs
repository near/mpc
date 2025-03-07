use crate::types::load_config;

#[derive(clap::Parser)]
pub enum Cli {
    /// Manage MPC networks
    Mpc(MpcNetworkCmd),
    /// Manage loadtest setups
    Loadtest(LoadtestCmd),
}

impl Cli {
    pub async fn run(self) {
        let config = load_config().await;
        match self {
            Cli::Mpc(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    MpcNetworkSubCmd::New(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::Update(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::RemoveContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::ViewContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::Join(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteJoin(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployInfra(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployNomad(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DestroyInfra(cmd) => {
                        cmd.run(&name, config).await;
                    }
                }
            }
            Cli::Loadtest(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    LoadtestSubCmd::New(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::Update(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::DeployParallelSignContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::Run(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::DrainExpiredRequests(cmd) => {
                        cmd.run(&name, config).await;
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
    DeployContract(MpcDeployContractCmd),
    RemoveContract(RemoveContractCmd),
    ViewContract(MpcViewContractCmd),
    Join(MpcJoinCmd),
    VoteJoin(MpcVoteJoinCmd),
    DeployInfra(MpcTerraformDeployInfraCmd),
    DeployNomad(MpcTerraformDeployNomadCmd),
    DestroyInfra(MpcTerraformDestroyInfraCmd),
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
    DrainExpiredRequests(DrainExpiredRequestsCmd),
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
pub struct MpcDeployContractCmd {
    /// File path that contains the contract code.
    #[clap(
        long,
        default_value = "../libs/chain-signatures/compiled-contracts/v1.0.1.wasm"
    )]
    pub path: String,
    /// The number of participants to initialize with.
    #[clap(long)]
    pub init_participants: usize,
    #[clap(long, default_value = "20")]
    pub deposit_near: u128,
    #[clap(long)]
    pub max_requests_to_remove: Option<u32>,
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
pub struct MpcTerraformDeployInfraCmd {
    #[clap(long)]
    pub reset_keyshares: bool,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDeployNomadCmd {
    #[clap(long)]
    pub shutdown_and_reset_db: bool,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDestroyInfraCmd {}

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
    #[clap(
        long,
        default_value = "../pytest/tests/test_contracts/parallel/res/contract.wasm"
    )]
    pub path: String,
    #[clap(long, default_value = "2")]
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

#[derive(clap::Parser)]
pub struct DrainExpiredRequestsCmd {
    #[clap(long)]
    pub mpc_network: String,
    #[clap(long, default_value = "1")]
    pub qps: usize,
}
