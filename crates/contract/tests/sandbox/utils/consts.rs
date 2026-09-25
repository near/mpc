use std::time::Duration;

use near_mpc_contract_interface::types::Protocol;
use near_sdk::Gas;

/* --- Protocol defaults --- */
pub const PARTICIPANT_LEN: usize = 10;
pub const ALL_PROTOCOLS: &[Protocol; 4] = &[
    Protocol::CaitSith,
    Protocol::Frost,
    Protocol::ConfidentialKeyDerivation,
    Protocol::RobustEcdsa,
];

/* --- Gas constants --- */
/// Convenience constant used only in tests. The contract itself does not require a specific
/// gas attachment; in practice, nodes usually attach the maximum available gas. For testing,
/// we use this constant to attach a fixed amount to each call and detect if gas usage
/// increases unexpectedly in the future.
pub const GAS_FOR_VOTE_RESHARED: Gas = Gas::from_tgas(65);
pub const GAS_FOR_VOTE_PK: Gas = Gas::from_tgas(22);
pub const GAS_FOR_INIT: Gas = Gas::from_tgas(300);

pub const DEFAULT_MAX_TIMEOUT_TX_INCLUDED: Duration = Duration::from_secs(3);
