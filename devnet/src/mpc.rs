#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::OperatingAccounts;
use crate::cli::{
    MpcDeployContractCmd, MpcJoinCmd, MpcViewContractCmd, MpcVoteJoinCmd, MpcVoteLeaveCmd,
    NewMpcNetworkCmd, RemoveContractCmd, UpdateMpcNetworkCmd,
};
use crate::constants::ONE_NEAR;
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::types::{MpcNetworkSetup, MpcParticipantSetup, ParsedConfig};
use legacy_mpc_contract::config::InitConfigV1;
use legacy_mpc_contract::primitives::{self, CandidateInfo, SignRequest};
use near_crypto::SecretKey;
use near_sdk::AccountId;
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

/// Bring the MPC network up to the desired parameterization.
async fn update_mpc_network(
    name: &str,
    accounts: &mut OperatingAccounts,
    mpc_setup: &mut MpcNetworkSetup,
    desired_num_participants: usize,
) {
    if desired_num_participants < mpc_setup.participants.len() {
        panic!(
            "Cannot reduce number of participants from {} to {}",
            mpc_setup.participants.len(),
            desired_num_participants
        );
    }

    // Create new participants as needed and refill existing participants' balances.
    // For each participant we maintain two accounts: the MPC account, and the responding account.
    let mut accounts_to_fund = Vec::new();
    for i in 0..desired_num_participants {
        if let Some(account_id) = mpc_setup.participants.get(i) {
            accounts_to_fund.push(AccountToFund::from_existing(
                account_id.clone(),
                mpc_setup.desired_balance_per_account,
            ));
            let participant = accounts
                .account(account_id)
                .get_mpc_participant()
                // We could recover from this, but that's too much work.
                .expect("Participant account is not marked as MPC participant");
            accounts_to_fund.push(AccountToFund::from_existing(
                participant.responding_account_id.clone(),
                mpc_setup.desired_balance_per_responding_account,
            ));
        } else {
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_account,
                format!("mpc-{}-{}-", i, name),
            ));
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_responding_account,
                format!("mpc-responder-{}-{}-", i, name),
            ));
        }
    }
    let funded_accounts = fund_accounts(accounts, accounts_to_fund).await;

    for i in mpc_setup.participants.len()..desired_num_participants {
        let account_id = funded_accounts[i * 2].clone();
        accounts
            .account_mut(&account_id)
            .set_mpc_participant(MpcParticipantSetup {
                p2p_private_key: SecretKey::from_random(near_crypto::KeyType::ED25519),
                responding_account_id: funded_accounts[i * 2 + 1].clone(),
            });
        mpc_setup.participants.push(account_id);
    }

    let responding_accounts = mpc_setup
        .participants
        .iter()
        .map(|participant| {
            accounts
                .account(participant)
                .get_mpc_participant()
                .unwrap()
                .responding_account_id
                .clone()
        })
        .collect::<Vec<_>>();

    // Ensure that the responding accounts have enough access keys.
    let futs = accounts
        .accounts_mut(&responding_accounts)
        .into_values()
        .map(|account| account.ensure_have_n_access_keys(mpc_setup.num_responding_access_keys))
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

impl NewMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to create MPC network {} with {} participants, threshold {}, {} NEAR per account, and {} additional access keys per participant for responding",
            name,
            self.num_participants,
            self.threshold,
            self.near_per_account,
            self.num_responding_access_keys,
        );

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        if setup.mpc_setups.contains_key(name) {
            panic!("MPC network {} already exists", name);
        }
        let mpc_setup = setup
            .mpc_setups
            .entry(name.to_string())
            .or_insert(MpcNetworkSetup {
                participants: Vec::new(),
                contract: None,
                threshold: self.threshold,
                desired_balance_per_account: self.near_per_account * ONE_NEAR,
                num_responding_access_keys: self.num_responding_access_keys,
                desired_balance_per_responding_account: self.near_per_responding_account * ONE_NEAR,
                nomad_server_url: None,
            });
        update_mpc_network(name, &mut setup.accounts, mpc_setup, self.num_participants).await;
    }
}

impl UpdateMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to update MPC network {}", name);

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));

        let num_participants = self
            .num_participants
            .unwrap_or(mpc_setup.participants.len());

        if let Some(threshold) = self.threshold {
            mpc_setup.threshold = threshold;
        }

        if let Some(near_per_account) = self.near_per_account {
            mpc_setup.desired_balance_per_account = near_per_account * ONE_NEAR;
        }

        if let Some(num_responding_access_keys) = self.num_responding_access_keys {
            mpc_setup.num_responding_access_keys = num_responding_access_keys;
        }

        if let Some(near_per_responding_account) = self.near_per_responding_account {
            mpc_setup.desired_balance_per_responding_account =
                near_per_responding_account * ONE_NEAR;
        }

        update_mpc_network(name, &mut setup.accounts, mpc_setup, num_participants).await;
    }
}

impl MpcDeployContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to deploy contract for MPC network {}", name);
        let contract_data = std::fs::read(&self.path).unwrap();
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if let Some(old_contract) = &mpc_setup.contract {
            let old_contract = setup
                .accounts
                .account(old_contract)
                .get_contract_code()
                .await
                .unwrap();
            if old_contract == contract_data {
                println!("Contract code is the same, not deploying");
                return;
            }
            println!("Contract code is different, going to redeploy");
        }

        let contract_account_to_fund = if let Some(contract) = &mpc_setup.contract {
            AccountToFund::ExistingAccount {
                account_id: contract.clone(),
                desired_balance: self.deposit_near * ONE_NEAR,
                do_not_refill_above: 0,
            }
        } else {
            AccountToFund::from_new(
                self.deposit_near * ONE_NEAR,
                format!("mpc-contract-{}-", name),
            )
        };
        let contract_account = fund_accounts(&mut setup.accounts, vec![contract_account_to_fund])
            .await
            .into_iter()
            .next()
            .unwrap();
        mpc_setup.contract = Some(contract_account.clone());

        setup
            .accounts
            .account_mut(&contract_account)
            .deploy_contract(contract_data, &self.path)
            .await;

        let mut access_key = setup
            .accounts
            .account(&contract_account)
            .any_access_key()
            .await;
        access_key
            .submit_tx_to_call_function(
                &contract_account,
                "init",
                &serde_json::to_vec(&InitArgs {
                    threshold: mpc_setup.threshold,
                    init_config: Some(InitConfigV1 {
                        max_num_requests_to_remove: self.max_requests_to_remove,
                        request_timeout_blocks: None,
                    }),
                    candidates: mpc_setup
                        .participants
                        .iter()
                        .take(self.init_participants)
                        .enumerate()
                        .map(|(i, account_id)| {
                            (
                                account_id.clone(),
                                mpc_account_to_candidate_info(&setup.accounts, account_id, i),
                            )
                        })
                        .collect(),
                })
                .unwrap(),
                300,
                0,
                near_primitives::views::TxExecutionStatus::Final,
                true,
            )
            .await
            .unwrap();
    }
}

#[derive(Serialize)]
struct InitArgs {
    threshold: usize,
    candidates: BTreeMap<AccountId, CandidateInfo>,
    init_config: Option<InitConfigV1>,
}

fn mpc_account_to_candidate_info(
    accounts: &OperatingAccounts,
    account_id: &AccountId,
    index: usize,
) -> CandidateInfo {
    let account = accounts.account(account_id);
    let mpc_setup = account.get_mpc_participant().unwrap();
    CandidateInfo {
        account_id: account_id.clone(),
        cipher_pk: [0; 32],
        sign_pk: near_sdk::PublicKey::from_str(&mpc_setup.p2p_private_key.public_key().to_string())
            .unwrap(),
        url: format!("http://mpc-node-{}.service.mpc.consul:3000", index),
    }
}

impl RemoveContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if mpc_setup.contract.is_some() {
            mpc_setup.contract = None;
            println!("Contract removed (not deleted; just removed from local view)");
        } else {
            println!("Contract is not deployed, nothing to do");
        }
    }
}

impl MpcViewContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let Some(contract) = mpc_setup.contract.as_ref() else {
            println!("Contract is not deployed");
            return;
        };
        let contract_state = setup
            .accounts
            .account(contract)
            .query_contract("state", b"{}".to_vec())
            .await
            .expect("state() call failed");
        println!(
            "Contract state: {}",
            String::from_utf8_lossy(&contract_state.result)
        );
    }
}

impl MpcJoinCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to join MPC network {} as participant {}",
            name, self.account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.account_index >= mpc_setup.participants.len() {
            panic!(
                "Account index {} is out of bounds for {} participants",
                self.account_index,
                mpc_setup.participants.len()
            );
        }
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let account = setup
            .accounts
            .account(&mpc_setup.participants[self.account_index]);
        let mut key = account.any_access_key().await;

        let candidate = mpc_account_to_candidate_info(
            &setup.accounts,
            &mpc_setup.participants[self.account_index],
            self.account_index,
        );
        key.submit_tx_to_call_function(
            &contract,
            "join",
            &serde_json::to_vec(&JoinArgs {
                url: candidate.url,
                cipher_pk: candidate.cipher_pk,
                sign_pk: candidate.sign_pk,
            })
            .unwrap(),
            300,
            0,
            near_primitives::views::TxExecutionStatus::Final,
            true,
        )
        .await
        .unwrap();
    }
}

#[derive(Serialize)]
struct JoinArgs {
    url: String,
    cipher_pk: primitives::hpke::PublicKey,
    sign_pk: near_sdk::PublicKey,
}

impl MpcVoteJoinCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_join MPC network {} for participant {}",
            name, self.for_account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.for_account_index >= mpc_setup.participants.len() {
            panic!(
                "Target account index {} is out of bounds for {} participants",
                self.for_account_index,
                mpc_setup.participants.len()
            );
        }
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let from_accounts = mpc_setup
            .participants
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                *i != self.for_account_index && (self.voters.is_empty() || self.voters.contains(i))
            })
            .map(|(_, account_id)| account_id)
            .collect::<Vec<_>>();

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let candidate = mpc_setup.participants[self.for_account_index].clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_join",
                    &serde_json::to_vec(&VoteJoinArgs { candidate }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(_) => {
                    println!(
                        "Participant {} vote_join({}) succeed",
                        i, self.for_account_index
                    );
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_join({}) failed: {:?}",
                        i, self.for_account_index, err
                    );
                }
            }
        }
    }
}

impl MpcVoteLeaveCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_leave MPC network {} for participant {}",
            name, self.for_account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.for_account_index >= mpc_setup.participants.len() {
            panic!(
                "Target account index {} is out of bounds for {} participants",
                self.for_account_index,
                mpc_setup.participants.len()
            );
        }
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let from_accounts = mpc_setup
            .participants
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                *i != self.for_account_index && (self.voters.is_empty() || self.voters.contains(i))
            })
            .map(|(_, account_id)| account_id)
            .collect::<Vec<_>>();

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let kick = mpc_setup.participants[self.for_account_index].clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_leave",
                    &serde_json::to_vec(&VoteLeaveArgs { kick }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(_) => {
                    println!(
                        "Participant {} vote_leave({}) succeed",
                        i, self.for_account_index
                    );
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_leave({}) failed: {:?}",
                        i, self.for_account_index, err
                    );
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteJoinArgs {
    candidate: AccountId,
}

#[derive(Serialize)]
struct VoteLeaveArgs {
    kick: AccountId,
}

#[derive(Serialize)]
pub struct SignArgs {
    pub request: SignRequest,
}
