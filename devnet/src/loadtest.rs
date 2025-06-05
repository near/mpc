#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccessKey, OperatingAccounts};
use crate::cli::{
    DeployParallelSignContractCmd, ListLoadtestCmd, NewLoadtestCmd, RunLoadtestCmd,
    UpdateLoadtestCmd,
};
use crate::constants::{DEFAULT_PARALLEL_SIGN_CONTRACT_PATH, ONE_NEAR};
use crate::contracts::{make_actions, ContractActionCall, ParallelSignCallArgs};
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
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::OwnedMutexGuard;

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
    contract_state: &mpc_contract::state::ProtocolContractState,
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

        let mut keys = Vec::new();
        for account_id in &loadtest_setup.load_senders {
            let account = setup.accounts.account(account_id);
            keys.extend(account.all_access_keys().await);
        }

        let parallel_sign_calls = self.parallel_sign_calls_per_domain.values().sum::<u64>();
        let tx_per_sec = if parallel_sign_calls > 0 {
            self.qps as f64 / parallel_sign_calls as f64
        } else {
            self.qps as f64
        };
        if tx_per_sec > config.rpc.total_qps() as f64 {
            println!("WARNING: Transactions to send per second is {}, but the RPC servers are only capable of handling an aggregate of {} QPS",
                tx_per_sec, config.rpc.total_qps());
        }
        let rpc_clone = config.rpc.clone();
        let contract_action: ContractActionCall = if parallel_sign_calls > 0 {
            let contract = loadtest_setup.parallel_signatures_contract.clone().expect(
                "Signatures per contract call specified, but no parallel signatures contract is deployed",
            );
            let contract_state = read_contract_state_v2(&setup.accounts, &mpc_account).await;
            let calls_by_domain: Vec<(DomainConfig, u64)> = self
                .parallel_sign_calls_per_domain
                .iter()
                .map(|(domain_id, n_calls)| {
                    (
                        get_domain_config(&contract_state, *domain_id)
                            .expect("require valid domain id"),
                        *n_calls,
                    )
                })
                .collect();
            let args = ParallelSignCallArgs {
                parallel_sign_contract: contract,
                mpc_contract: mpc_account,
                calls_by_domain,
            };
            crate::contracts::ContractActionCall::ParallelSignCall(args)
        } else if let Some(domain_id) = self.domain_id {
            let contract_state = read_contract_state_v2(&setup.accounts, &mpc_account).await;
            ContractActionCall::Sign(crate::contracts::SignActionCallArgs {
                mpc_contract: mpc_account,
                domain_config: get_domain_config(&contract_state, domain_id)
                    .expect("require valid domain id"),
            })
        } else {
            ContractActionCall::LegacySign(crate::contracts::LegacySignActionCallArgs {
                mpc_contract: mpc_account,
            })
        };
        let action_call = make_actions(contract_action);
        let sender: LoadSenderAsyncFn = {
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
        // todo:
        // - cancellation token to stop after x seconds
        // - verification function & track stats
        let (tx_sender, mut receiver): (Sender<TxRpcResponse>, Receiver<TxRpcResponse>) =
            tokio::sync::mpsc::channel(100);
        let rpc_clone = config.rpc.clone();
        let res_handle = tokio::spawn(async move {
            let mut n_rpc_requests = 0;
            let mut n_rpc_errors = 0;
            let mut txs: Vec<SignedTransaction> = Vec::new();
            while let Some(x) = receiver.recv().await {
                n_rpc_requests += 1;
                match x.rpc_response {
                    Err(e) => {
                        n_rpc_errors += 1;
                        eprintln!("Error sending rpc request: {:?}", e);
                    }
                    Ok(_) => {
                        txs.push(x.signed_tx);
                    }
                }
            }
            println!(
                "{:.2}% RPC requests succeeded. Received {} errors out of / {} requests.",
                ((n_rpc_requests - n_rpc_errors) as f64 / n_rpc_requests as f64),
                n_rpc_errors,
                n_rpc_requests
            );

            println!("Collecting Signature Responses");
            let n_txs = txs.len();
            let mut failed = 0;
            for tx in &txs {
                let request = methods::EXPERIMENTAL_tx_status::RpcTransactionStatusRequest {
                    transaction_info:
                        methods::EXPERIMENTAL_tx_status::TransactionInfo::Transaction(near_jsonrpc_primitives::types::transactions::SignedTransaction::SignedTransaction(tx.clone())) ,
                    wait_until: TxExecutionStatus::Final,
                };
                let res = rpc_clone.submit(request).await.unwrap();
                let Some(res) = res.final_execution_outcome else {
                    failed += 1;
                    continue;
                };
                let res_status = res.into_outcome().status;
                let FinalExecutionStatus::SuccessValue(_sig) = res_status else {
                    println!("Signature {:?}\n failed with:\n{:?}", tx, res_status);
                    failed += 1;
                    continue;
                };
                // todo: verify signature
                // todo: use ticks
                let waiting_time = 1000 / config.rpc.total_qps();
                tokio::time::sleep(Duration::from_millis(waiting_time as u64)).await;
            }
            println!(
                "{} / {} signatures failed. Success Rate: {:.2}",
                failed,
                n_txs,
                (n_txs - failed) as f64 / n_txs as f64
            );
        });
        let cancel: tokio_util::sync::CancellationToken =
            tokio_util::sync::CancellationToken::new();

        let join_set = send_load(keys, tx_per_sec, sender, tx_sender, cancel.clone()).await;
        if let Some(duration) = self.duration {
            tokio::time::sleep(Duration::from_secs(duration)).await;
            cancel.cancel();
        }
        join_set.join_all().await;

        let _ = res_handle.await;
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
    res_sender: tokio::sync::mpsc::Sender<TxRpcResponse>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinSet<()> {
    let mut join_set = tokio::task::JoinSet::new();
    let (permits_sender, permits_receiver) = flume::bounded(qps.ceil() as usize);
    for mut key in keys {
        let permits_receiver = permits_receiver.clone();
        let res_sender_clone = res_sender.clone();
        let sender = sender.clone();
        join_set.spawn(async move {
            while permits_receiver.recv_async().await.is_ok() {
                let resp = sender(&mut key).await;
                res_sender_clone.send(resp).await.unwrap();
            }
        });
    }
    join_set.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs_f64(1.0 / qps));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    if permits_sender.send_async(()).await.is_err() {
                        // add an error message
                        break;
                    }
                }
            }
        }
    });

    join_set
}
