use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::TcbInfo;
use near_mpc_contract_interface::types as dtos;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct VerificationContext {
    pub(crate) node: dtos::Node,
    pub(crate) tcb_info: TcbInfo,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::node_for;
    use test_utils::attestation::mock_tcb_info;

    /// Every dstack submission pays for these bytes twice, once to send the callback
    /// receipt and once to execute it. Sized to reject a re-added quote (the smaller of
    /// the two payloads this context deliberately leaves behind) while leaving the TCB
    /// info room to grow.
    const MAX_CALLBACK_ARG_BYTES: usize = 8 * 1024;

    #[test]
    fn verification_context__should_serialize_within_the_callback_arg_budget() {
        // Given
        let context = VerificationContext {
            node: node_for(&"alice.near".parse().unwrap()),
            tcb_info: mock_tcb_info(),
        };

        // When
        let serialized = borsh::to_vec(&context).unwrap();

        // Then
        assert!(
            serialized.len() <= MAX_CALLBACK_ARG_BYTES,
            "callback arg is {} bytes, over the {MAX_CALLBACK_ARG_BYTES} byte budget",
            serialized.len(),
        );
    }
}
