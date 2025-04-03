use crate::account::{make_random_account_name, OperatingAccount, OperatingAccounts};
use crate::constants::{
    MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS, ONE_NEAR,
    PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL,
};
use crate::types::NearAccount;
use near_sdk::AccountId;
use std::collections::VecDeque;

/// An account to request funding for.
pub enum AccountToFund {
    /// Create a new account with the given prefix and initial balance.
    /// The account will be in the form of {prefix}-{random_string}.{funding_account}
    NewAccount {
        initial_balance: u128,
        prefix: String,
    },
    /// Refill an existing account to the desired balance, but do not refill if it's
    /// above a balance of `do_not_refill_above`.
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

/// Funds the given accounts, drawing from existing funding accounts when available, and creating
/// new funding accounts from the faucet if needed. Any number of accounts and any amount of balance
/// can be funded, up to a sanity limit of 100 NEAR total.
pub async fn fund_accounts(
    accounts: &mut OperatingAccounts,
    desired_funding: Vec<AccountToFund>,
    funding_account: Option<NearAccount>,
) -> Vec<AccountId> {
    // Funding accounts that we already have, and their usable balances.
    // We assume that MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS is enough to cover transfer fees.
    let mut funding_accounts = accounts
        .get_account_balances(&accounts.get_funding_accounts())
        .await
        .into_iter()
        .map(|(account_id, balance)| {
            (
                account_id,
                balance.saturating_sub(MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS),
            )
        })
        .collect::<VecDeque<_>>();
    // Funding accounts that have been drained completely and should be deleted from our db.
    let mut funding_accounts_to_delete = Vec::new();

    // Accounts already fully funded.
    let mut funded_accounts = Vec::new();
    // Each represents an account to fund plus how much balance it still needs.
    // funded_accounts + accounts_to_be_funded remains the same elements and order as
    // desired_funding.
    let mut accounts_to_be_funded: VecDeque<(AccountToFund, u128)> = VecDeque::new();
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
                    0
                } else {
                    *desired_balance - balance
                }
            }
        };
        accounts_to_be_funded.push_back((account, balance_needed));
    }
    if accounts_to_be_funded
        .iter()
        .map(|(_, balance)| balance)
        .sum::<u128>()
        > 100 * ONE_NEAR
    {
        panic!("Refusing to fund more than 100 NEAR at once, as it would drain too much of the faucet.");
    }

    while !accounts_to_be_funded.is_empty() {
        // Make sure we have at least 1 funding account; if not, use the provided one or create from faucet
        if funding_accounts.is_empty() {
            if let Some(funding_account) = &funding_account {
                println!(
                    "Using provided funding account {} from config",
                    funding_account.account_id
                );
                // Add the account to our operating accounts if not already there
                if !accounts.accounts.contains_key(&funding_account.account_id) {
                    accounts.accounts.insert(
                        funding_account.account_id.clone(),
                        OperatingAccount::new(
                            funding_account.clone(),
                            accounts.recent_block_hash,
                            accounts.client.clone(),
                        ),
                    );
                }
                let balance = accounts
                    .get_account_balance(&funding_account.account_id)
                    .await;
                funding_accounts.push_back((
                    funding_account.account_id.clone(),
                    balance.saturating_sub(MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS),
                ));
            } else {
                let funding_account = make_random_account_name("", ".testnet");
                println!(
                    "Creating new funding account {} from faucet",
                    funding_account
                );
                accounts
                    .create_funding_account_from_faucet(&funding_account)
                    .await;
                let balance = accounts.get_account_balance(&funding_account).await;
                funding_accounts.push_back((
                    funding_account,
                    balance.saturating_sub(MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS),
                ));
            }
        }

        // Look at the first funding account we have, and try to use that to fund as much of the
        // account as we can.
        let (funding_account, balance) = funding_accounts.pop_front().unwrap();
        if balance < MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS {
            // We may be creating a new account, and it's probably not good to start the new account
            // with a very low balance. So just throw it away if the funding account is too low.
            println!(
                "Funding account {} is exhausted; discarding",
                funding_account
            );
            funding_accounts_to_delete.push(funding_account);
            continue;
        }

        let (account_to_fund, balance_needed) = accounts_to_be_funded.pop_front().unwrap();
        let balance_to_fund = balance.min(balance_needed);
        let balance_remaining_in_funding_account = balance - balance_to_fund;
        let balance_remaining_to_fund = balance_needed - balance_to_fund;

        if balance_remaining_in_funding_account > 0 {
            // If the funding account still has balance, put it back so we can use it again.
            funding_accounts.push_front((
                funding_account.clone(),
                balance_remaining_in_funding_account,
            ));
        } else {
            funding_accounts_to_delete.push(funding_account.clone());
        }

        let account_id = match &account_to_fund {
            AccountToFund::NewAccount { prefix, .. } => {
                accounts
                    .create_account(prefix, balance_to_fund, &funding_account)
                    .await
            }
            AccountToFund::ExistingAccount { account_id, .. } => {
                if balance_to_fund > 0 {
                    println!(
                        "Refilling existing account {} with additional balance {}",
                        account_id, balance_to_fund
                    );
                    accounts
                        .send_balance(&funding_account, account_id, balance_to_fund)
                        .await;
                }
                account_id.clone()
            }
        };
        if balance_remaining_to_fund > 0 {
            // It's possible that we didn't fully fund the account, so we put it back and continue.
            accounts_to_be_funded.push_front((
                AccountToFund::ExistingAccount {
                    account_id: account_id.clone(),
                    // These don't matter anymore.
                    desired_balance: 0,
                    do_not_refill_above: 0,
                },
                balance_remaining_to_fund,
            ));
        } else {
            funded_accounts.push(account_id);
        }
    }

    // Delete the funding accounts that have been exhausted.
    for account in funding_accounts_to_delete {
        accounts.discard_account(&account);
    }
    funded_accounts
}
