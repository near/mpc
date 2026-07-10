use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::DstackAttestation;

use super::tee_state::NodeId;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct VerificationContext {
    pub(crate) node_id: NodeId,
    pub(crate) attestation: DstackAttestation,
    pub(crate) caller_is_participant: bool,
}
