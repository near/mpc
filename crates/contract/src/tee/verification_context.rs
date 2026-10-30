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
    use near_mpc_contract_interface::types::Ed25519PublicKey;
    use test_utils::attestation::{account_key, mock_tcb_info, p2p_tls_key};

    /// Every dstack submission pays for these bytes twice, once to send the callback
    /// receipt and once to execute it. Sized to reject a re-added quote (the smaller of
    /// the two payloads this context deliberately leaves behind) while leaving the TCB
    /// info room to grow.
    const MAX_CALLBACK_ARG_BYTES: usize = 8 * 1024;

    #[test]
    fn verification_context__should_serialize_within_the_callback_arg_budget() {
        // Given
        let context = VerificationContext {
            node: dtos::Node {
                account_id: "alice.near".parse().unwrap(),
                tls_public_key: Ed25519PublicKey(p2p_tls_key()),
                account_public_key: Ed25519PublicKey(account_key()),
            },
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
