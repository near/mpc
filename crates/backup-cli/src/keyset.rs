use near_mpc_contract_interface::types::Keyset;

/// The newest concluded keyset, which is the only one worth backing up, from the output of the
/// contract's `current_keyset` view.
pub fn keyset_to_backup(current_keyset: Option<Keyset>) -> Result<Keyset, NoKeysetToBackUp> {
    let keyset = current_keyset.ok_or(NoKeysetToBackUp::NoConcludedKeyset)?;
    if keyset.domains.is_empty() {
        return Err(NoKeysetToBackUp::NoKeysGenerated);
    }
    Ok(keyset)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NoKeysetToBackUp {
    #[error("contract has no concluded keyset: it is not initialized or is generating keys")]
    NoConcludedKeyset,
    #[error("contract has concluded no key generation yet")]
    NoKeysGenerated,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    use near_mpc_contract_interface::types::EpochId;
    use rstest::rstest;

    use crate::test_utils::{keyset_with_epoch, keyset_without_domains};

    #[test]
    fn keyset_to_backup__should_return_the_current_keyset() {
        // Given
        let current_keyset = Some(keyset_with_epoch(5));

        // When
        let keyset = keyset_to_backup(current_keyset).unwrap();

        // Then
        assert_eq!(keyset.epoch_id, EpochId::new(5));
    }

    #[rstest]
    #[case::no_keyset(None, NoKeysetToBackUp::NoConcludedKeyset)]
    #[case::keyset_without_domains(
        Some(keyset_without_domains()),
        NoKeysetToBackUp::NoKeysGenerated
    )]
    fn keyset_to_backup__should_fail_without_a_concluded_keyset(
        #[case] current_keyset: Option<Keyset>,
        #[case] expected_error: NoKeysetToBackUp,
    ) {
        // When
        let error = keyset_to_backup(current_keyset).unwrap_err();

        // Then
        assert_eq!(error, expected_error);
    }
}
