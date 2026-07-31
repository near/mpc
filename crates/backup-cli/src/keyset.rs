use near_mpc_contract_interface::types::{Keyset, ProtocolContractState};

/// The newest concluded keyset, which is the only one worth backing up.
pub fn keyset_to_backup(contract_state: &ProtocolContractState) -> Result<Keyset, NoKeysetInState> {
    let keyset = match contract_state {
        ProtocolContractState::NotInitialized => return Err(NoKeysetInState::NotInitialized),
        ProtocolContractState::Initializing(_) => return Err(NoKeysetInState::Initializing),
        ProtocolContractState::Resharing(state) => &state.previous_running_state.keyset,
        ProtocolContractState::Running(state) => &state.keyset,
    };
    if keyset.domains.is_empty() {
        return Err(NoKeysetInState::NoKeysGenerated);
    }
    Ok(keyset.clone())
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NoKeysetInState {
    #[error("contract is not initialized, no key has been generated yet")]
    NotInitialized,
    #[error("contract is generating keys, the keyset is not concluded yet")]
    Initializing,
    #[error("contract has concluded no key generation yet")]
    NoKeysGenerated,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_mpc_contract_interface::types::EpochId;
    use rstest::rstest;

    use super::*;
    use crate::test_utils::{
        must_get_fixture_epoch_id, must_get_initializing_state, must_get_resharing_state,
        must_get_running_state_with_epoch, must_get_running_state_without_domains,
    };

    #[test]
    fn keyset_to_backup__should_return_the_keyset_of_a_running_state() {
        // Given
        let state = must_get_running_state_with_epoch(5);

        // When
        let keyset = keyset_to_backup(&state).unwrap();

        // Then
        assert_eq!(keyset.epoch_id, EpochId::new(5));
    }

    #[test]
    fn keyset_to_backup__should_return_the_previous_keyset_while_resharing() {
        // Given
        let state = must_get_resharing_state();

        // When
        let keyset = keyset_to_backup(&state).unwrap();

        // Then
        assert_eq!(keyset.epoch_id, must_get_fixture_epoch_id());
        assert!(!keyset.domains.is_empty());
    }

    #[rstest]
    #[case::not_initialized(ProtocolContractState::NotInitialized, NoKeysetInState::NotInitialized)]
    #[case::initializing(must_get_initializing_state(), NoKeysetInState::Initializing)]
    #[case::running_without_domains(
        must_get_running_state_without_domains(),
        NoKeysetInState::NoKeysGenerated
    )]
    fn keyset_to_backup__should_fail_without_a_concluded_keyset(
        #[case] state: ProtocolContractState,
        #[case] expected_error: NoKeysetInState,
    ) {
        // When
        let error = keyset_to_backup(&state).unwrap_err();

        // Then
        assert_eq!(error, expected_error);
    }
}
