use std::time::Duration;

use mpc_contract::primitives::domain::SignatureScheme;
use near_sdk::{Gas, NearToken};

/* --- Protocol defaults --- */
pub const PARTICIPANT_LEN: usize = 10;
pub const ALL_SIGNATURE_SCHEMES: &[SignatureScheme; 4] = &[
    SignatureScheme::Secp256k1,
    SignatureScheme::Ed25519,
    SignatureScheme::Bls12381,
    SignatureScheme::V2Secp256k1,
];

/* --- Gas constants --- */
/// Convenience constant used only in tests. The contract itself does not require a specific
/// gas attachment; in practice, nodes usually attach the maximum available gas. For testing,
/// we use this constant to attach a fixed amount to each call and detect if gas usage
/// increases unexpectedly in the future.
///
/// TODO(#926) this gas was bumped from 22 to 34 in https://github.com/near/mpc/pull/1559. This
/// might be due to the high cost of `self.protocol_state = new_state` in the vote_reshard
/// contract call. This needs to be investigated to understand why the increase was necessary.
pub const GAS_FOR_VOTE_RESHARED: Gas = Gas::from_tgas(34);
pub const GAS_FOR_VOTE_PK: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_CANCEL_KEYGEN: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_CANCEL_RESHARING: Gas = Gas::from_tgas(5);
pub const GAS_FOR_VOTE_NEW_DOMAIN: Gas = Gas::from_tgas(22);
pub const GAS_FOR_VOTE_NEW_PARAMETERS: Gas = Gas::from_tgas(22);
/// TODO(#1571): Gas cost for voting on contract updates. Reduced somewhat after
/// optimization (#1617) by avoiding full contract code deserialization; there’s likely still
/// room for further optimization.
pub const GAS_FOR_VOTE_UPDATE: Gas = Gas::from_tgas(232);
/// Gas required for votes cast before the threshold is reached (votes 1 through N-1).
/// These votes are cheap because they only record the vote without triggering the actual
/// contract update deployment and migration.
pub const GAS_FOR_VOTE_BEFORE_THRESHOLD: Gas = Gas::from_tgas(5);
/// Maximum gas expected for the threshold vote that triggers the contract update.
/// This vote is more expensive because it deploys the new contract code and executes
/// the migration function.
pub const MAX_GAS_FOR_THRESHOLD_VOTE: Gas = Gas::from_tgas(147);

/* --- Deposit constants --- */
/// This is the current deposit required for a contract deploy. This is subject to change but make
/// sure that it's not larger than 2mb. We can go up to 4mb technically but our contract should
/// not be getting that big.
///
/// TODO(#771): Reduce this to the minimal value possible after #770 is resolved
pub const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(13000);

pub const DEFAULT_MAX_TIMEOUT_TX_INCLUDED: Duration = Duration::from_secs(3);
