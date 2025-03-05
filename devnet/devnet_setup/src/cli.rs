use crate::account::{make_random_account_name, OperatingAccounts};
use crate::rpc::NearRpcClients;
use crate::types::{Config, DevnetSetup, DevnetSetupRepository, LoadtestSetup};
use near_jsonrpc_client::methods;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[derive(clap::Parser)]
pub enum Cli {
    NewDevnet(NewDevnetCmd),
    NewLoadtest(NewLoadtestCmd),
}

impl Cli {
    pub async fn run(self) {
        const CONFIG_FILE: &str = "config.yaml";
        let config = std::fs::read_to_string(CONFIG_FILE).unwrap();
        let config: Config = serde_yaml::from_str(&config).unwrap();
        let client = Arc::new(NearRpcClients::new(config.rpcs).await);

        match self {
            Cli::NewDevnet(_) => {
                unimplemented!()
            }
            Cli::NewLoadtest(cmd) => cmd.run(client).await,
        }
    }
}

#[derive(clap::Parser)]
pub struct NewDevnetCmd {
    pub name: String,
    #[clap(long)]
    pub num_participants: usize,
    #[clap(long)]
    pub threshold: usize,
}

#[derive(clap::Parser)]
pub struct NewLoadtestCmd {
    pub name: String,
    #[clap(long)]
    pub num_accounts: usize,
    #[clap(long)]
    pub keys_per_account: usize,
    #[clap(long)]
    pub near_per_account: u128,
}

struct OperatingDevnetSetup {
    accounts: OperatingAccounts,
    mpc_setups: HashMap<String, DevnetSetup>,
    loadtest_setups: HashMap<String, LoadtestSetup>,
}

impl OperatingDevnetSetup {
    const SETUP_FILENAME: &str = "devnet_setup.json";

    pub async fn load(client: Arc<NearRpcClients>) -> Self {
        if !std::fs::exists(Self::SETUP_FILENAME).unwrap() {
            std::fs::write(
                Self::SETUP_FILENAME,
                serde_json::to_string(&DevnetSetupRepository::default()).unwrap(),
            )
            .unwrap();
        }
        let setup_data = std::fs::read_to_string(Self::SETUP_FILENAME).unwrap();
        let setup: DevnetSetupRepository = serde_json::from_str(&setup_data).unwrap();

        let recent_block_hash = client
            .lease()
            .await
            .call(methods::block::RpcBlockRequest {
                block_reference: near_primitives::types::BlockReference::Finality(
                    near_primitives::types::Finality::Final,
                ),
            })
            .await
            .unwrap()
            .header
            .hash;

        let accounts = OperatingAccounts::new(setup.accounts, recent_block_hash, client);
        Self {
            accounts,
            mpc_setups: setup.mpc_setups,
            loadtest_setups: setup.loadtest_setups,
        }
    }
}

impl Drop for OperatingDevnetSetup {
    fn drop(&mut self) {
        let setup = DevnetSetupRepository {
            accounts: self.accounts.to_data(),
            mpc_setups: self.mpc_setups.clone(),
            loadtest_setups: self.loadtest_setups.clone(),
        };
        let setup_data = serde_json::to_string(&setup).unwrap();
        if std::fs::exists(OperatingDevnetSetup::SETUP_FILENAME).unwrap() {
            std::fs::rename(
                OperatingDevnetSetup::SETUP_FILENAME,
                format!("{}.bak", OperatingDevnetSetup::SETUP_FILENAME),
            )
            .unwrap();
        }
        std::fs::write(OperatingDevnetSetup::SETUP_FILENAME, setup_data).unwrap();
    }
}

const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const USEFUL_FUNDING_PER_FAUCET_ACCOUNT: u128 = 9 * ONE_NEAR;
const MAX_FAUCET_ACCOUNTS_TO_USE: usize = 10;

impl NewLoadtestCmd {
    pub async fn run(&self, client: Arc<NearRpcClients>) {
        println!("Going to create loadtest account set {} with {} loadtest accounts, each with {} keys (total {} keys) and {} NEAR",
            self.name,
            self.num_accounts,
            self.keys_per_account,
            self.num_accounts * self.keys_per_account,
            self.near_per_account,
        );

        let mut setup = OperatingDevnetSetup::load(client).await;
        if setup.loadtest_setups.contains_key(&self.name) {
            panic!("Loadtest setup with name {} already exists", self.name);
        }
        let needed_near = self.near_per_account * self.num_accounts as u128;

        let mut funding_accounts = setup.accounts.get_funding_accounts();
        let mut funding_account_balances =
            setup.accounts.get_account_balances(&funding_accounts).await;
        let total_useful_funding = funding_account_balances
            .iter()
            .map(|(_, balance)| balance.saturating_sub(1 * ONE_NEAR))
            .sum::<u128>();
        if total_useful_funding < needed_near {
            let num_faucets_needed =
                (needed_near - total_useful_funding + USEFUL_FUNDING_PER_FAUCET_ACCOUNT - 1)
                    / USEFUL_FUNDING_PER_FAUCET_ACCOUNT;
            if num_faucets_needed > MAX_FAUCET_ACCOUNTS_TO_USE as u128 {
                panic!(
                    "Refusing to create too many faucet accounts; would need {}",
                    num_faucets_needed
                );
            }
            let num_faucets_needed = num_faucets_needed as usize;
            println!("Going to create {} faucet accounts", num_faucets_needed);
            for _ in 0..num_faucets_needed {
                let faucet_account_id = make_random_account_name("-mpc-loadtest.testnet");
                setup
                    .accounts
                    .create_account_from_faucet(faucet_account_id)
                    .await;
            }
            funding_accounts = setup.accounts.get_funding_accounts();
            funding_account_balances = setup.accounts.get_account_balances(&funding_accounts).await;
        } else {
            println!("Have enough funding accounts; going to reuse them");
        }

        let mut funding_account_balances = funding_account_balances
            .into_iter()
            .filter(|(_, balance)| *balance >= 1 * ONE_NEAR)
            .map(|(account_id, balance)| (account_id, balance.saturating_sub(1 * ONE_NEAR)))
            .collect::<VecDeque<_>>();
        let mut created_accounts = Vec::new();
        for _ in 0..self.num_accounts {
            let funding_account = loop {
                let (funding_account_id, balance) = funding_account_balances.pop_front().unwrap();
                if balance >= self.near_per_account {
                    break funding_account_id;
                }
                funding_account_balances.pop_front();
            };
            let account_id = make_random_account_name(&format!(".{}", funding_account.as_str()));
            setup
                .accounts
                .create_account(
                    account_id.clone(),
                    self.near_per_account * ONE_NEAR,
                    &funding_account,
                )
                .await;
            created_accounts.push(account_id);
        }

        setup.loadtest_setups.insert(
            self.name.clone(),
            LoadtestSetup {
                load_senders: created_accounts.clone(),
            },
        );

        let futs = setup
            .accounts
            .accounts_mut(&created_accounts)
            .into_iter()
            .map(|(_, account)| account.ensure_have_n_access_keys(self.keys_per_account))
            .collect::<Vec<_>>();
        futures::future::join_all(futs).await;
    }
}
