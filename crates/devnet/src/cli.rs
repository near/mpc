use std::collections::BTreeMap;

use anyhow::Context;
use near_sdk::AccountId;

use crate::types::load_config;

#[derive(clap::Parser)]
pub enum Cli {
    /// Manage MPC networks
    Mpc(MpcNetworkCmd),
    /// Manage loadtest setups
    Loadtest(LoadtestCmd),
    /// List loadtests or mpc networks
    List(ListCmd),
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
                    MpcNetworkSubCmd::InitContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::RemoveContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::ViewContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::ProposeUpdateContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteUpdate(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteAddDomains(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteNewParameters(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteCodeHash(cmd) => {
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
                    MpcNetworkSubCmd::Describe(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::AddKeys(cmd) => {
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
                }
            }
            Cli::List(cmd) => match cmd.subcmd {
                ListSubCmd::Mpc(cmd) => {
                    cmd.run(config).await;
                }
                ListSubCmd::Loadtest(cmd) => {
                    cmd.run(config).await;
                }
            },
        }
    }
}

#[derive(clap::Parser)]
pub struct ListCmd {
    #[clap(subcommand)]
    pub subcmd: ListSubCmd,
}
#[derive(clap::Parser)]
pub struct ListMpcCmd {}

#[derive(clap::Parser)]
pub struct ListLoadtestCmd {}

#[derive(clap::Parser)]
pub enum ListSubCmd {
    /// Lists all mpc setups
    Mpc(ListMpcCmd),
    /// Lists all loadtest setups
    Loadtest(ListLoadtestCmd),
}

#[derive(clap::Parser)]
pub struct MpcNetworkCmd {
    /// A friendly name of the MPC network; use a unique name in the team.
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: MpcNetworkSubCmd,
}

#[derive(clap::Parser)]
pub struct MpcAddKeysCmd {}

#[derive(clap::Parser)]
pub enum MpcNetworkSubCmd {
    /// Create a new MPC network.
    New(NewMpcNetworkCmd),
    /// Update the parameters of an existing MPC network, including refilling accounts.
    Update(UpdateMpcNetworkCmd),
    /// Deploy the MPC contract code (without initializing it).
    DeployContract(MpcDeployContractCmd),
    /// Initialize the MPC contract, initializing it to the specified parameters.
    InitContract(MpcInitContractCmd),
    /// fetch data from `get_public_data` and add the keys.
    AddKeys(MpcAddKeysCmd),
    /// Remove the MPC contract from the local state, so a fresh one can be deployed.
    RemoveContract(RemoveContractCmd),
    /// View the contract state.
    ViewContract(MpcViewContractCmd),
    /// Send a propose_update() transaction to propose an update to the contract.
    ProposeUpdateContract(MpcProposeUpdateContractCmd),
    /// Send vote_update() transactions to the contract to vote on an update.
    VoteUpdate(MpcVoteUpdateCmd),
    /// Send vote_add_domains() transactions to vote for adding domains.
    VoteAddDomains(MpcVoteAddDomainsCmd),
    /// Send vote_new_parameters() transactions to vote for new parameters.
    VoteNewParameters(MpcVoteNewParametersCmd),
    /// Send `vote_code_hash()` transactions to vote for a new approved MPC image hash.
    VoteCodeHash(MpcVoteApprovedHashCmd),
    /// Deploy the GCP nodes with Terraform to host Nomad jobs to run this network.
    DeployInfra(MpcTerraformDeployInfraCmd),
    /// Deploy the Nomad jobs to run this network.
    DeployNomad(MpcTerraformDeployNomadCmd),
    /// Destroy the GCP nodes previously deployed.
    DestroyInfra(MpcTerraformDestroyInfraCmd),
    /// Prints out useful information about the contract and/or the deployed infra.
    Describe(MpcDescribeCmd),
}

#[derive(clap::Parser)]
pub struct LoadtestCmd {
    /// A friendly name of the loadtest setup.
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: LoadtestSubCmd,
}

#[derive(clap::Parser)]
pub enum LoadtestSubCmd {
    /// Creates a new loadtest setup.
    New(NewLoadtestCmd),
    /// Refills accounts in the loadtest setup, and optionally create more accounts or keys.
    Update(UpdateLoadtestCmd),
    /// Deploy the parallel signature request contract for sending load faster.
    DeployParallelSignContract(DeployParallelSignContractCmd),
    /// Send load to an MPC network.
    Run(RunLoadtestCmd),
}

#[derive(clap::Parser)]
pub struct NewMpcNetworkCmd {
    /// Number of participants that will participant in the network at some point. This can be
    /// increased later, but it's recommended to pick the highest number you intend to use,
    /// because initializing new machines is slow.
    #[clap(long)]
    pub num_participants: usize,
    /// The amount of NEAR to give to each MPC account. This is NOT the account that will be used
    /// to send signature responses, so you do NOT need to give a lot to these accounts.
    #[clap(long, default_value = "1")]
    pub near_per_account: u128,
    /// Number of additional access keys per participant to add for the responding account.
    #[clap(long)]
    pub num_responding_access_keys: usize,
    /// The amount of NEAR to give to each responding account. This is the account that will be used
    /// to send signature responses, so depending on the number of access keys, you may want to give
    /// higher amounts here.
    #[clap(long, default_value = "1")]
    pub near_per_responding_account: u128,
    /// Indicates if the machines should be using SSD
    #[clap(long, default_value = "false")]
    pub ssd: bool,
}

#[derive(clap::Parser)]
pub struct UpdateMpcNetworkCmd {
    #[clap(long)]
    pub num_participants: Option<usize>,
    #[clap(long)]
    pub near_per_account: Option<u128>,
    #[clap(long)]
    pub num_responding_access_keys: Option<usize>,
    #[clap(long)]
    pub near_per_responding_account: Option<u128>,
}

#[derive(clap::Parser)]
pub struct MpcInitContractCmd {
    /// The number of participants to initialize with; the participants will be from 0 to
    /// init_participants-1.
    #[clap(long)]
    pub init_participants: usize,
    /// The threshold to initialize with.
    #[clap(long)]
    pub threshold: u64,
}

#[derive(clap::Parser)]
pub struct MpcDeployContractCmd {
    /// File path that contains the contract code.
    /// If not set, then the contract from TESTNET_CONTRACT_ACCOUNT_ID is fetched and deployed.
    #[clap(long)]
    pub path: Option<String>,
    /// The number of NEAR to deposit into the contract account, for storage deposit.
    #[clap(long, default_value = "20")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct RemoveContractCmd {}

#[derive(clap::Parser)]
pub struct MpcViewContractCmd {}

#[derive(clap::Parser)]
pub struct MpcProposeUpdateContractCmd {
    /// The index of the participant that proposes the update.
    #[clap(long, default_value = "0")]
    pub proposer_index: usize,
    /// The file path to the new contract wasm code.
    #[clap(long)]
    pub path: String,
    /// The deposit to send along with the proposal.
    #[clap(long, default_value = "8")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct MpcVoteUpdateCmd {
    /// The ID of the update, as printed by the propose-update-contract command.
    #[clap(long)]
    pub update_id: u64,
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub struct MpcVoteAddDomainsCmd {
    #[clap(long, value_delimiter = ',')]
    pub schemes: Vec<String>,
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub struct MpcVoteNewParametersCmd {
    /// The new threshold to set; if not set, the current threshold will be used.
    #[clap(long)]
    pub set_threshold: Option<u64>,
    /// The indices of the participants to add to the network.
    #[clap(long)]
    pub add: Vec<usize>,
    /// The indices of the participants to remove from the network.
    #[clap(long)]
    pub remove: Vec<usize>,
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub(crate) struct MpcVoteApprovedHashCmd {
    /// The Docker image hash to approve on the contract.
    #[clap(long, value_parser = Self::mpc_docker_image_hash_parser)]
    pub mpc_docker_image_hash: [u8; 32],
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

impl MpcVoteApprovedHashCmd {
    fn mpc_docker_image_hash_parser(value: &str) -> anyhow::Result<[u8; 32]> {
        hex::decode(value)
            .context("image hash is not a valid hex string")?
            .try_into()
            .map_err(|_| anyhow::Error::msg("Image hash is not 32 bytes"))
    }
}

#[derive(clap::Parser)]
pub struct MpcTerraformDeployInfraCmd {
    /// If true, deletes the keyshares from the GCP secrets manager. This is useful if you wish to
    /// deploy a new contract and need to re-generate the key.
    #[clap(long)]
    pub reset_keyshares: bool,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDeployNomadCmd {
    /// If true, shuts down and reset the MPC nodes, leaving only the nearcore data.
    #[clap(long)]
    pub shutdown_and_reset: bool,
    /// Overrides the docker image to use for MPC nodes.
    /// The default is `constants::DEFAULT_MPC_DOCKER_IMAGE`.
    #[clap(long)]
    pub docker_image: Option<String>,
    /// By default, we deploy the default docker image, which is a legacy node, requiring secret
    /// shares.
    /// Set this flag if you deploy a newer node that generates its secrets on its own.
    #[clap(long)]
    pub not_legacy: bool, // todo: remove [(#710)](https://github.com/near/mpc/issues/710)
}

#[derive(clap::Parser)]
pub struct MpcTerraformDestroyInfraCmd {}

#[derive(clap::Parser)]
pub struct MpcDescribeCmd {}

#[derive(clap::Parser)]
pub struct NewLoadtestCmd {
    /// The number of accounts to create for the loadtest setup.
    /// It is recommended to just use 1 account. You can use more if you want to test functionality
    /// of handling multiple accounts. However, the number of access keys is what matters, not the
    /// number of accounts.
    #[clap(long)]
    pub num_accounts: usize,
    /// Number of access keys to add per account. This is the number of parallel requests that can
    /// be issued at once.
    #[clap(long)]
    pub keys_per_account: usize,
    /// Amount of NEAR to give to each account. This should be chosen based on how much gas is
    /// expected to be used for concurrently running requests. For example, if you were going to
    /// send 300Tgas transactions with 100 access keys, and each transaction is going to take 5
    /// blocks, then there is a concurrency of 500 transactions. Then you'll need however many
    /// NEAR to cover 150Pgas of compute. Or, just reduce the gas limit you use to something much
    /// lower.
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
    /// Defaults to `constants::DEFAULT_PARALLEL_SIGN_CONTRACT_PATH`.
    #[clap(long)]
    pub path: Option<String>,
    #[clap(long, default_value = "20")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct RunLoadtestCmd {
    /// The name of the MPC network to run the loadtest against.
    /// Set either this OR the mpc_contract variable.
    #[clap(long)]
    pub mpc_network: Option<String>,
    /// The address of the MPC contract to query.
    #[clap(long)]
    pub mpc_contract: Option<AccountId>,
    /// The QPS to send. The loadtest framework will try to send this many
    /// signature requests per second.
    #[clap(long)]
    pub qps: usize,
    /// The number of signatures to send per parallel-signature contract call.
    /// Pass as --parallel-sign-calls-per-domain 0=3,1=2,2=3
    /// This will be divided into the QPS, so you don't need to change the QPS flag.
    #[clap(long, value_parser = parse_parallel_calls)]
    pub parallel_sign_calls_per_domain: Option<BTreeMap<u64, u64>>,
    /// Domain ID. If missing, use legacy signature format. Is ignored if
    /// `signatures_per_contract_call` is set.
    #[clap(long)]
    pub domain_id: Option<u64>,
    /// Duration for loadtest (in seconds). If not set, the test runs indefinitely.
    #[clap(long)]
    pub duration: Option<u64>,
}

fn parse_parallel_calls(s: &str) -> Result<BTreeMap<u64, u64>, String> {
    let mut map = BTreeMap::new();
    for pair in s.split(',') {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid pair '{}'", pair))?;
        let key = k.trim().parse().map_err(|_| format!("bad key '{}'", k))?;
        let val = v.trim().parse().map_err(|_| format!("bad value '{}'", v))?;
        map.insert(key, val);
    }
    Ok(map)
}
