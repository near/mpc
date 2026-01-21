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
use crate::mpc::read_contract_state;
use crate::types::{LoadtestSetup, NearAccount, ParsedConfig};
use anyhow::anyhow;
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_jsonrpc_client::methods::send_tx;
use near_jsonrpc_client::methods::tx::{RpcTransactionResponse, TransactionInfo};
use near_jsonrpc_client::methods::EXPERIMENTAL_tx_status::RpcTransactionStatusRequest;
use near_primitives::transaction::SignedTransaction;
use near_primitives::views::{FinalExecutionStatus, TxExecutionStatus};
use std::f64;
use std::io::{stdout, Write};
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
            println!("Loadtest setup with name {} already exists. Fetching the existing loadtest and updating.", name);
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

impl RunLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));
        let mpc_account = match (&self.mpc_contract, &self.mpc_network) {
            (Some(contract), None) => {
                println!(
                    "Going to run loadtest setup {} against MPC contract {} at {} QPS",
                    name, contract, self.qps
                );
                contract.clone()
            }
            (None, Some(network)) => {
                let mpc_setup = setup
                    .mpc_setups
                    .get(network)
                    .expect(&format!("MPC network with name {} does not exist", network));
                let mpc_account = mpc_setup
                    .contract
                    .clone()
                    .expect("MPC network does not have a contract");
                println!(
                    "Going to run loadtest setup {} against MPC network {} (contract {}) at {} QPS",
                    name, network, mpc_account, self.qps
                );
                mpc_account.clone()
            }
            _ => panic!("Require either the mpc contract account id or the mpc network name"),
        };

        let mut keys = Vec::new();
        for account_id in &loadtest_setup.load_senders {
            let account = setup.accounts.account(account_id);
            keys.extend(account.all_access_keys().await);
        }

        let parallel_sign_calls = self
            .parallel_sign_calls_per_domain
            .as_ref()
            .map(|m| m.values().sum::<u64>())
            .unwrap_or(0);
        let tx_per_sec = if parallel_sign_calls > 0 {
            f64::from(self.qps) / f64::try_from(parallel_sign_calls).expect("parallel_sign_calls fits in f64")
        } else {
            f64::from(self.qps)
        };
        if tx_per_sec > f64::try_from(config.rpc.total_qps()).expect("total_qps fits in f64") {
            println!("WARNING: Transactions to send per second is {}, but the RPC servers are only capable of handling an aggregate of {} QPS",
                tx_per_sec, config.rpc.total_qps());
        }
        let rpc_clone = config.rpc.clone();
        let contract_action: ContractActionCall = if parallel_sign_calls > 0 {
            let contract = loadtest_setup.parallel_signatures_contract.clone().expect(
                "Signatures per contract call specified, but no parallel signatures contract is deployed",
            );
            let contract_state = read_contract_state(&config.rpc, &mpc_account).await;
            let calls_by_domain: Vec<(DomainConfig, u64)> = self
                .parallel_sign_calls_per_domain
                .as_ref()
                .unwrap()
                .iter()
                .map(|(domain_id, n_calls)| {
                    (
                        contract_state
                            .get_domain_config(DomainId(*domain_id))
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
            let contract_state = read_contract_state(&config.rpc, &mpc_account).await;
            let domain_config = contract_state
                .get_domain_config(DomainId(domain_id))
                .expect("require valid domain id");
            match domain_config.scheme {
                SignatureScheme::Bls12381 => {
                    ContractActionCall::Ckd(crate::contracts::RequestActionCallArgs {
                        mpc_contract: mpc_account,
                        domain_config,
                    })
                }
                SignatureScheme::Ed25519
                | SignatureScheme::Secp256k1
                | SignatureScheme::V2Secp256k1 => {
                    ContractActionCall::Sign(crate::contracts::RequestActionCallArgs {
                        mpc_contract: mpc_account,
                        domain_config,
                    })
                }
            }
        } else {
            ContractActionCall::LegacySign(crate::contracts::LegacySignActionCallArgs {
                mpc_contract: mpc_account,
            })
        };
        let sender: LoadSenderAsyncFn = {
            Arc::new(move |key: &mut OperatingAccessKey| {
                let action_call = make_actions(contract_action.clone());
                let rpc_clone = rpc_clone.clone();
                async move {
                    let signed_tx = key.sign_tx_from_actions(action_call).await;

                    let rpc_response = rpc_clone
                        .submit(send_tx::RpcSendTransactionRequest {
                            signed_transaction: signed_tx.clone(),
                            wait_until: near_primitives::views::TxExecutionStatus::Included,
                        })
                        .await
                        .map_err(|e| anyhow!("error sending tx request: {}", e));
                    TxRpcResponse {
                        rpc_response,
                        signed_tx,
                    }
                }
                .boxed()
            })
        };
        let (tx_sender, mut receiver): (Sender<TxRpcResponse>, Receiver<TxRpcResponse>) =
            tokio::sync::mpsc::channel(100);
        let rpc_clone = config.rpc.clone();
        let parallel = if parallel_sign_calls > 0 {
            "parallel "
        } else {
            ""
        };
        // if we have an unlimited duration, no need to store any data, as we need to cancel the
        // program.
        let store_data = self.duration.is_some();
        let res_handle = tokio::spawn(async move {
            let mut n_rpc_requests = 0;
            let mut n_rpc_errors = 0;
            let mut txs: Vec<SignedTransaction> = Vec::new();
            let mut rpc_errs: Vec<String> = Vec::new();
            while let Some(x) = receiver.recv().await {
                n_rpc_requests += 1;
                match x.rpc_response {
                    Err(e) => {
                        n_rpc_errors += 1;
                        if store_data {
                            rpc_errs.push(e.to_string());
                        }
                    }
                    Ok(_) => {
                        if store_data {
                            txs.push(x.signed_tx);
                        }
                    }
                }
                print!(
                    "\rSubmitted {} {}signature requests. Received {} RPC errors",
                    n_rpc_requests, parallel, n_rpc_errors
                );
                let _ = stdout().flush();
            }
            println!(
                "\rSubmitted {} {}signature requests. Received {} RPC errors",
                n_rpc_requests, parallel, n_rpc_errors
            );
            // note: we will never enter here if loadtest runs indefinetly.
            if !rpc_errs.is_empty() {
                println!("Rpc errors:");
                for e in &rpc_errs {
                    eprintln!("{}", e);
                }
            }
            rpc_errs.clear();

            println!("Collecting Signature Responses");
            let mut succeeded = 0;
            let mut failures = vec![];
            for tx in &txs {
                print!(
                    "\rFound {} {}signature responses and {} failures. Encountered {} rpc errors.",
                    succeeded,
                    parallel,
                    failures.len(),
                    rpc_errs.len(),
                );
                for _ in 0..10 {
                    let waiting_time =
                        1000 / u64::try_from(config.rpc.total_qps()).expect("total_qps fits in u64");
                    tokio::time::sleep(Duration::from_millis(waiting_time)).await;
                    let request = RpcTransactionStatusRequest{
                    transaction_info:
                        TransactionInfo::Transaction(near_jsonrpc_primitives::types::transactions::SignedTransaction::SignedTransaction(tx.clone())),
                    wait_until: TxExecutionStatus::Final,
                    };
                    match rpc_clone.submit(request).await {
                        Ok(res) => {
                            let res = res
                                .final_execution_outcome
                                .expect("Expected a final execution outcome or an RPC error.");
                            let res_status = res.into_outcome().status;
                            if let FinalExecutionStatus::SuccessValue(_sig) = res_status {
                                succeeded += 1;
                            } else {
                                failures.push(res_status);
                            };
                            break;
                        }
                        Err(e) => {
                            rpc_errs.push(e.to_string());
                        }
                    }
                }
            }
            println!(
                "\rFound {} {}signature responses and {} failures. Encountered {} rpc errors.",
                succeeded,
                parallel,
                failures.len(),
                rpc_errs.len(),
            );

            if !rpc_errs.is_empty() {
                println!("Rpc errors:");
                for e in &rpc_errs {
                    eprintln!("{}", e);
                }
            }
            if !failures.is_empty() {
                println!("Signature failures:");
                for e in &failures {
                    eprintln!("{:?}", e);
                }
            }
            println!("Success Rate: {}%", (succeeded * 100) / txs.len());
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
    let (permits_sender, permits_receiver) =
        flume::bounded(usize::try_from(qps.ceil()).expect("qps.ceil() fits in usize"));
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
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    if permits_sender.send_async(()).await.is_err() {
                        eprintln!("sender closed unexpectedly");
                        break;
                    }
                }
            }
        }
    });

    join_set
}
