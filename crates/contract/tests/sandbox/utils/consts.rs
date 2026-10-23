use std::time::Duration;

use near_mpc_contract_interface::types::Protocol;

/* --- Protocol defaults --- */
pub const PARTICIPANT_LEN: usize = 10;
pub const ALL_PROTOCOLS: &[Protocol; 4] = &[
    Protocol::CaitSith,
    Protocol::Frost,
    Protocol::ConfidentialKeyDerivation,
    Protocol::RobustEcdsa,
];

pub const DEFAULT_MAX_TIMEOUT_TX_INCLUDED: Duration = Duration::from_secs(3);
