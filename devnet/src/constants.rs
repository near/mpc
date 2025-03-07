pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Below this minimum balance we consider an account to be possibly unusable.
pub const MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS: u128 = ONE_NEAR / 10;
/// When we need to refill an account (during an update operation), we will not
/// refill it if it's more than this percent of the desired balance. That way, we don't
/// end up topping up accounts all the time with tiny amounts.
pub const PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL: u128 = 70;
