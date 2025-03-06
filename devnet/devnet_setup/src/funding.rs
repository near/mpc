use crate::account::{make_random_account_name, OperatingAccounts};
use crate::constants::{
    MINIMUM_BALANCE_TO_REMAIN_IN_FUNDING_ACCOUNTS,
    PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL,
};
use near_sdk::AccountId;
use std::collections::VecDeque;

pub enum AccountToFund {
    NewAccount {
        initial_balance: u128,
        prefix: String,
    },
    ExistingAccount {
        account_id: AccountId,
        desired_balance: u128,
        do_not_refill_above: u128,
    },
}

impl AccountToFund {
    pub fn from_new(initial_balance: u128, prefix: String) -> Self {
        Self::NewAccount {
            initial_balance,
            prefix,
        }
    }

    pub fn from_existing(account_id: AccountId, desired_balance: u128) -> Self {
        Self::ExistingAccount {
            account_id,
            desired_balance,
            do_not_refill_above: desired_balance
                * PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL
                / 100,
        }
    }
}

pub async fn fund_accounts(
    accounts: &mut OperatingAccounts,
    desired_funding: Vec<AccountToFund>,
) -> Vec<AccountId> {
    let mut funding_accounts = accounts
        .get_account_balances(&accounts.get_funding_accounts())
        .await
        .into_iter()
        .collect::<VecDeque<_>>();
    let mut funded_accounts = Vec::new();
    for account in desired_funding {
        let balance_needed = match &account {
            AccountToFund::NewAccount {
                initial_balance, ..
            } => *initial_balance,
            AccountToFund::ExistingAccount {
                account_id,
                desired_balance,
                do_not_refill_above,
            } => {
                let balance = accounts.get_account_balance(account_id).await;
                if balance >= *do_not_refill_above {
                    println!(
                        "Existing account {} does not need refilling; has balance {}",
                        account_id, balance
                    );
                    funded_accounts.push(account_id.clone());
                    continue;
                }
                *desired_balance - balance
            }
        };
        let funding_account = loop {
            if funding_accounts.is_empty() {
                let funding_account = make_random_account_name("", "-funding.testnet");
                accounts
                    .create_funding_account_from_faucet(&funding_account)
                    .await;
                funding_accounts.push_back((funding_account.clone(), 0));
                break funding_account;
            } else {
                let (funding_account, mut balance) = funding_accounts.pop_front().unwrap();
                if balance < balance_needed + MINIMUM_BALANCE_TO_REMAIN_IN_FUNDING_ACCOUNTS {
                    continue;
                }
                balance -= balance_needed;
                funding_accounts.push_front((funding_account.clone(), balance));
                break funding_account;
            }
        };

        let account_id = match account {
            AccountToFund::NewAccount {
                initial_balance,
                prefix,
            } => {
                accounts
                    .create_account(&prefix, initial_balance, &funding_account)
                    .await
            }
            AccountToFund::ExistingAccount { account_id, .. } => {
                println!(
                    "Refilling existing account {} with additional balance {}",
                    account_id, balance_needed
                );
                accounts
                    .send_balance(&funding_account, &account_id, balance_needed)
                    .await;
                account_id
            }
        };
        funded_accounts.push(account_id);
    }
    funded_accounts
}
