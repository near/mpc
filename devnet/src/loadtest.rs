#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccessKey, OperatingAccounts};
use crate::cli::{
    DeployParallelSignContractCmd, ListLoadtestCmd, NewLoadtestCmd, RunLoadtestCmd,
    UpdateLoadtestCmd,
};
use crate::constants::{DEFAULT_PARALLEL_SIGN_CONTRACT_PATH, ONE_NEAR};
use crate::contracts::{ActionCall, MpcContract, ParallelSignContract};
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::mpc::read_contract_state_v2;
use crate::rpc::NearRpcClients;
use crate::types::{LoadtestSetup, NearAccount, ParsedConfig};
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_contract::primitives::domain::DomainConfig;
use near_jsonrpc_client::methods;
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_primitives::transaction::SignedTransaction;
use near_primitives::views::{FinalExecutionStatus, TxExecutionStatus};
use std::f64;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::OwnedMutexGuard;
use tokio::time::timeout;

impl ListLoadtestCmd {
    pub async fn run(&self, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setups = &setup.loadtest_setups;
        for (name, setup) in loadtest_setups {
            println!("{}: {}", name, setup);
        }
    }
}

/// Bring the loadtest setup to the desired parameterization.
async fn update_loadtest_setup(
    name: &str,
    accounts: &mut OperatingAccounts,
    loadtest_setup: &mut LoadtestSetup,
    desired_num_accounts: usize,
    funding_account: Option<NearAccount>,
) {
    // First create any accounts we don't already have, and refill existing.
    let mut accounts_to_fund = Vec::new();
    for i in 0..desired_num_accounts {
        if let Some(account_id) = loadtest_setup.load_senders.get(i) {
            accounts_to_fund.push(AccountToFund::from_existing(
                account_id.clone(),
                loadtest_setup.desired_balance_per_account,
            ));
        } else {
            accounts_to_fund.push(AccountToFund::from_new(
                loadtest_setup.desired_balance_per_account,
                format!("loadtest-{}-{}-", i, name),
            ));
        }
    }
    let funded_accounts = fund_accounts(accounts, accounts_to_fund, funding_account).await;

    loadtest_setup.load_senders = funded_accounts.clone();

    // Ensure that each account has the desired number of access keys.
    let futs = accounts
        .accounts_mut(&funded_accounts)
        .into_values()
        .map(|account| account.ensure_have_n_access_keys(loadtest_setup.desired_keys_per_account))
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

impl NewLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to create loadtest setup {} with {} loadtest accounts, each with {} keys (total {} keys) and {} NEAR",
            name,
            self.num_accounts,
            self.keys_per_account,
            self.num_accounts * self.keys_per_account,
            self.near_per_account,
        );

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        if setup.loadtest_setups.contains_key(name) {
            println!("Loadtest setup with name {} already exists, updating", name);
        }
        let loadtest_setup = setup
            .loadtest_setups
            .entry(name.to_string())
            .or_insert(Default::default());

        loadtest_setup.desired_balance_per_account = self.near_per_account * ONE_NEAR;
        loadtest_setup.desired_keys_per_account = self.keys_per_account;

        update_loadtest_setup(
            name,
            &mut setup.accounts,
            loadtest_setup,
            self.num_accounts,
            config.funding_account,
        )
        .await;
    }
}

impl ListLoadtestCmd {
    pub async fn run(&self, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setups = &setup.loadtest_setups;
        for (name, setup) in loadtest_setups {
            println!("{}: {}", name, setup);
        }
    }
}

impl UpdateLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to update loadtest setup {}", name);

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get_mut(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));

        let desired_num_accounts = self
            .num_accounts
            .unwrap_or(loadtest_setup.load_senders.len());
        if let Some(keys_per_account) = self.keys_per_account {
            loadtest_setup.desired_keys_per_account = keys_per_account;
        }
        if let Some(near_per_account) = self.near_per_account {
            loadtest_setup.desired_balance_per_account = near_per_account * ONE_NEAR;
        }

        update_loadtest_setup(
            name,
            &mut setup.accounts,
            loadtest_setup,
            desired_num_accounts,
            config.funding_account,
        )
        .await;
    }
}

impl DeployParallelSignContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to deploy parallel sign contract for loadtest setup {}",
            name
        );
        let contract_path = self
            .path
            .clone()
            .unwrap_or(DEFAULT_PARALLEL_SIGN_CONTRACT_PATH.to_string());
        let contract_data = std::fs::read(&contract_path).unwrap();

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get_mut(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));

        if let Some(old_contract) = &loadtest_setup.parallel_signatures_contract {
            let old_contract = setup
                .accounts
                .account(old_contract)
                .get_contract_code()
                .await
                .unwrap_or_default();
            if old_contract == contract_data {
                println!("Contract code is the same, not deploying");
                return;
            }
            println!("Contract code is different, going to redeploy");
        }

        let contract_account_to_fund =
            if let Some(contract) = &loadtest_setup.parallel_signatures_contract {
                AccountToFund::ExistingAccount {
                    account_id: contract.clone(),
                    desired_balance: self.deposit_near * ONE_NEAR,
                    do_not_refill_above: 0,
                }
            } else {
                AccountToFund::from_new(self.deposit_near * ONE_NEAR, format!("par-sign-{}-", name))
            };
        let contract_account = fund_accounts(
            &mut setup.accounts,
            vec![contract_account_to_fund],
            config.funding_account,
        )
        .await
        .into_iter()
        .next()
        .unwrap();
        loadtest_setup.parallel_signatures_contract = Some(contract_account.clone());

        setup
            .accounts
            .account_mut(&contract_account)
            .deploy_contract(contract_data, &contract_path)
            .await;
    }
}

pub fn get_domain_config(
    contract_state: mpc_contract::state::ProtocolContractState,
    domain_id: u64,
) -> Option<DomainConfig> {
    match contract_state {
        mpc_contract::state::ProtocolContractState::Running(state) => state
            .domains
            .domains()
            .iter()
            .find(|domain| domain.id.0 == domain_id)
            .cloned(),
        mpc_contract::state::ProtocolContractState::Resharing(state) => state
            .previous_running_state
            .domains
            .domains()
            .iter()
            .find(|domain| domain.id.0 == domain_id)
            .cloned(),
        _ => {
            panic!("MPC network is not running or resharing");
        }
    }
}

pub async fn submit_tx_to_client(
    client: Arc<NearRpcClients>,
    signed_transaction: SignedTransaction,
    wait_until: TxExecutionStatus,
) -> anyhow::Result<RpcTransactionResponse> {
    let request = methods::send_tx::RpcSendTransactionRequest {
        signed_transaction,
        wait_until,
    };
    Ok(client.submit(request).await?)
}
impl RunLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));
        let mpc_setup = setup.mpc_setups.get(&self.mpc_network).expect(&format!(
            "MPC network with name {} does not exist",
            self.mpc_network
        ));
        let mpc_account = mpc_setup
            .contract
            .clone()
            .expect("MPC network does not have a contract");
        println!(
            "Going to run loadtest setup {} against MPC network {} (contract {}) at {} QPS",
            name, self.mpc_network, mpc_account, self.qps
        );

        let domain_config = if let Some(domain_id) = self.domain_id {
            let contract_state = read_contract_state_v2(&setup.accounts, &mpc_account).await;
            get_domain_config(contract_state, domain_id)
        } else {
            None
        };

        let mut keys = Vec::new();
        for account_id in &loadtest_setup.load_senders {
            let account = setup.accounts.account(account_id);
            keys.extend(account.all_access_keys().await);
        }

        let tx_per_sec =
            if let Some(signatures_per_contract_call) = self.signatures_per_contract_call {
                self.qps as f64 / signatures_per_contract_call as f64
            } else {
                self.qps as f64
            };
        if tx_per_sec > config.rpc.total_qps() as f64 {
            println!("WARNING: Transactions to send per second is {}, but the RPC servers are only capable of handling an aggregate of {} QPS",
                tx_per_sec, config.rpc.total_qps());
        }
        let mpc_contract = MpcContract {
            account: mpc_account.clone(),
        };
        let rpc_clone = config.rpc.clone();
        let sender: LoadSenderAsyncFn = if let Some(signatures_per_contract_call) =
            self.signatures_per_contract_call
        {
            let contract = loadtest_setup.parallel_signatures_contract.clone().expect(
                "Signatures per contract call specified, but no parallel signatures contract is deployed",
            );
            let parallel_sign_contract = ParallelSignContract {
                account_id: contract,
                mpc_contract: mpc_account,
            };
            Arc::new(move |key: &mut OperatingAccessKey| {
                let parallel_sign_contract = parallel_sign_contract.clone();
                let domain_config = domain_config.clone().expect("require domain");
                let rpc_clone = rpc_clone.clone();
                async move {
                    let signed_tx = key
                        .sign_tx_from_actions(
                            parallel_sign_contract.make_parallel_sign_call_action(
                                domain_config,
                                signatures_per_contract_call as u64,
                            ),
                        )
                        .await;
                    TxRpcResponse {
                        rpc_response: submit_tx_to_client(
                            rpc_clone,
                            signed_tx.clone(),
                            near_primitives::views::TxExecutionStatus::Included,
                        )
                        .await,
                        signed_tx,
                    }
                }
                .boxed()
            })
        } else {
            let action_call: ActionCall = if let Some(domain_config) = &domain_config {
                mpc_contract.make_sign_action(domain_config.clone())
            } else {
                mpc_contract.make_legacy_sign_action()
            };
            //if let Some(domain_config) = domain_config {
            //   // todo: pass args (signature request) by channel for verification.
            Arc::new(move |key: &mut OperatingAccessKey| {
                let action_call_cloned = action_call.clone();
                let rpc_clone = rpc_clone.clone();
                async move {
                    let signed_tx = key.sign_tx_from_actions(action_call_cloned).await;
                    // send signed_tx through a channel to await response
                    TxRpcResponse {
                        rpc_response: submit_tx_to_client(
                            rpc_clone,
                            signed_tx.clone(),
                            near_primitives::views::TxExecutionStatus::Included,
                        )
                        .await,
                        signed_tx,
                    }
                }
                .boxed()
            })
        };
        let (tx_sender, mut receiver): (Sender<SignedTransaction>, Receiver<SignedTransaction>) =
            tokio::sync::mpsc::channel(100);
        let rpc_clone = config.rpc.clone();
        tokio::spawn(async move {
            let mut txs: Vec<SignedTransaction> = Vec::new();
            while let Some(x) = receiver.recv().await {
                txs.push(x);
            }

            let n_txs = txs.len();
            let mut failed = 0;
            for tx in txs {
                let request = methods::EXPERIMENTAL_tx_status::RpcTransactionStatusRequest {
                    transaction_info:
                        methods::EXPERIMENTAL_tx_status::TransactionInfo::Transaction(near_jsonrpc_primitives::types::transactions::SignedTransaction::SignedTransaction(tx)) ,
                    wait_until: TxExecutionStatus::Final,
                };
                let res = rpc_clone.submit(request).await.unwrap();
                let Some(res) = res.final_execution_outcome else {
                    failed += 1;
                    continue;
                };
                let FinalExecutionStatus::SuccessValue(sig) = res.into_outcome().status else {
                    failed += 1;
                    continue;
                };
                // todo: verify signature
                println!("{:?}", sig);
                // adjust sleep time to not owerwhelm rpc node
                //
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            println!(
                "{} / {} signatures failed. Success Rate: {}",
                failed,
                n_txs,
                (n_txs - failed) as f64 / n_txs as f64
            );
        });
        // alternatively, timeout here?
        send_load(
            keys,
            tx_per_sec,
            sender,
            Some(tx_sender),
            self.duration.map(Duration::from_secs),
        )
        .await;
    }
}

pub struct TxRpcResponse {
    pub rpc_response: anyhow::Result<RpcTransactionResponse>,
    pub signed_tx: SignedTransaction,
}

type LoadSenderAsyncFn = Arc<
    dyn for<'a> Fn(&'a mut OperatingAccessKey) -> BoxFuture<'a, TxRpcResponse>
        + Send
        + Sync
        + 'static,
>;

/// Send parallel load up to the given QPS (may fluctuate within a second),
/// using the sender function. The sender function will only be executed once at a time for each
/// access key, so enough access keys would be needed to saturate the QPS.
/// Also, the rpc client will internally apply rate limits, so that's another possible bottleneck.
async fn send_load(
    keys: Vec<OwnedMutexGuard<OperatingAccessKey>>,
    qps: f64,
    sender: LoadSenderAsyncFn,
    res_sender: Option<tokio::sync::mpsc::Sender<SignedTransaction>>,
    duration: Option<Duration>,
) {
    let mut handles = Vec::new();
    let (permits_sender, permits_receiver) = flume::bounded(qps.ceil() as usize);
    let total_txns_sent = Arc::new(AtomicUsize::new(0));
    let total_errors = Arc::new(AtomicUsize::new(0));
    for mut key in keys {
        let permits_receiver = permits_receiver.clone();
        let total_txns_sent = total_txns_sent.clone();
        let total_errors = total_errors.clone();
        let res_sender_clone = res_sender.clone();
        let sender = sender.clone();
        handles.push(tokio::spawn(async move {
            loop {
                permits_receiver.recv_async().await.unwrap();
                let resp = sender(&mut key).await;
                match resp.rpc_response {
                    Err(e) => {
                        total_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("Error sending transaction: {:?}", e);
                    }
                    Ok(_) => {
                        if let Some(c) = &res_sender_clone {
                            if let Err(e) = c.send(resp.signed_tx).await {
                                println!("got error {}", e);
                            }
                        }
                    }
                }
                total_txns_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    // todo: store request / response in a database for that run, allowing to retrieve them and
    // check for e.g. derivation path preservation etc.
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs_f64(1.0 / qps));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            permits_sender.send_async(()).await.unwrap();
        }
    }));

    let total_txns_sent = total_txns_sent.clone();
    let total_errors = total_errors.clone();
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_total = 0;
        let mut last_error_total = 0;
        loop {
            interval.tick().await;
            let txns_sent = total_txns_sent.load(std::sync::atomic::Ordering::Relaxed);
            let errors = total_errors.load(std::sync::atomic::Ordering::Relaxed);
            println!(
                "Sent {} transactions, {} errors ({} successful QPS)",
                txns_sent,
                errors,
                (txns_sent - last_total) - (errors - last_error_total)
            );
            last_total = txns_sent;
            last_error_total = errors;
        }
    }));

    if let Some(duration) = duration {
        // we will always get an error here
        if let Err(e) = timeout(duration, futures::future::join_all(handles)).await {
            // todo: gracously stop. Wait for all transactions to conclude.
            println!("Stopping loadtest: {}", e);
        }
    } else {
        futures::future::join_all(handles).await;
    }
}
