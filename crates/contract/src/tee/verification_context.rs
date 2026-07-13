use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::tcb_info::TcbInfo;

use super::tee_state::NodeId;

/// State threaded from `submit_participant_info` to the `resolve_verification`
/// callback. Carries only the [`TcbInfo`] — the quote and collateral are
/// consumed by the verifier's DCAP step and are not needed for the post-DCAP
/// checks, so echoing them through the callback receipt would only inflate it.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct VerificationContext {
    pub(crate) node_id: NodeId,
    pub(crate) tcb_info: TcbInfo,
}
