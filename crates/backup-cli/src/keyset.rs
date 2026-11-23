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

    use rstest::rstest;

    use crate::test_utils::{fixture_keyset, keyset_without_domains};

    #[rstest]
    #[case::concluded_keyset(Some(fixture_keyset()), Ok(fixture_keyset()))]
    #[case::no_keyset(None, Err(NoKeysetToBackUp::NoConcludedKeyset))]
    #[case::keyset_without_domains(
        Some(keyset_without_domains()),
        Err(NoKeysetToBackUp::NoKeysGenerated)
    )]
    fn keyset_to_backup__should_return_only_a_concluded_keyset(
        #[case] current_keyset: Option<Keyset>,
        #[case] expected: Result<Keyset, NoKeysetToBackUp>,
    ) {
        // When
        let keyset = keyset_to_backup(current_keyset);

        // Then
        assert_eq!(keyset, expected);
    }
}
