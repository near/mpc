use std::time::Duration;

use near_mpc_contract_interface::types::Protocol;
use near_sdk::{Gas, NearToken};

/* --- Protocol defaults --- */
pub const PARTICIPANT_LEN: usize = 10;
pub const ALL_PROTOCOLS: &[Protocol; 4] = &[
    Protocol::CaitSith,
    Protocol::Frost,
    Protocol::ConfidentialKeyDerivation,
    Protocol::DamgardEtAl,
];

/* --- Gas constants --- */
/// Convenience constant used only in tests. The contract itself does not require a specific
/// gas attachment; in practice, nodes usually attach the maximum available gas. For testing,
/// we use this constant to attach a fixed amount to each call and detect if gas usage
/// increases unexpectedly in the future.
pub const GAS_FOR_VOTE_RESHARED: Gas = Gas::from_tgas(44);
pub const GAS_FOR_VOTE_PK: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_CANCEL_KEYGEN: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_CANCEL_RESHARING: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_NEW_DOMAIN: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_NEW_PARAMETERS: Gas = Gas::from_tgas(22);
pub const GAS_FOR_INIT: Gas = Gas::from_tgas(300);
/// TODO(#1571): Gas cost for voting on contract updates. Reduced somewhat after
/// optimization (#1617) by avoiding full contract code deserialization; there’s likely still
/// room for further optimization.
/// Bumped 260 → 290 TGas after the `Votes<V>` + `IterableMap` migration grew the
/// reproducible WASM. The threshold vote spawns `deploy_contract(code)` whose
/// action cost scales with code size; the prior 260 TGas budget was failing with
/// `Exceeded the prepaid gas` once `burnt + promises_gas` crossed the limit
/// (`test_propose_update_contract_many` in particular).
pub const GAS_FOR_VOTE_UPDATE: Gas = Gas::from_tgas(290);
/// Gas required for votes cast before the threshold is reached (votes 1 through N-1).
/// These votes are cheap because they only record the vote without triggering the actual
/// contract update deployment and migration.
pub const GAS_FOR_VOTE_BEFORE_THRESHOLD: Gas = Gas::from_tgas(5);
/// Maximum gas expected for the threshold vote that triggers the contract update.
/// This vote is more expensive because it deploys the new contract code and executes
/// the migration function. Raised from 185 to 190 TGas to accommodate the larger
/// WASM and additional `pr1_state` try-read step added by the foreign-chain RPC
/// providers feature (issue #3215); revert toward 185 once `pr1_state` is retired.
pub const MAX_GAS_FOR_THRESHOLD_VOTE: Gas = Gas::from_tgas(190);

/* --- Deposit constants --- */
/// This is the current deposit required for a contract deploy. This is subject to change but make
/// sure that it's not larger than 2mb. We can go up to 4mb technically but our contract should
/// not be getting that big.
///
/// TODO(#2756): Reduce this to the minimal value possible
pub const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(17000);

pub const DEFAULT_MAX_TIMEOUT_TX_INCLUDED: Duration = Duration::from_secs(3);
