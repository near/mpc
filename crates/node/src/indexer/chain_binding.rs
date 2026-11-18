use anyhow::ensure;
use near_indexer::near_primitives::hash::CryptoHash;

/// Fails if there is an expected genesis hash and the node follows another chain
pub fn ensure_chain_matches_contract(
    expected_genesis_hash: Option<CryptoHash>,
    genesis_hash: CryptoHash,
) -> anyhow::Result<()> {
    if let Some(expected_genesis_hash) = expected_genesis_hash {
        ensure!(
            genesis_hash == expected_genesis_hash,
            "the contract runs on the chain with genesis {expected_genesis_hash}, \
             but this node follows the chain with genesis {genesis_hash}"
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    const GENESIS_HASH: CryptoHash = CryptoHash([1; 32]);

    #[rstest]
    #[case::same_chain(Some(GENESIS_HASH), true)]
    #[case::other_chain(Some(CryptoHash([2; 32])), false)]
    #[case::no_expected_chain(None, true)]
    fn ensure_chain_matches_contract__should_reject_a_chain_other_than_the_expected_one(
        #[case] expected_genesis_hash: Option<CryptoHash>,
        #[case] accepted: bool,
    ) {
        // When
        let result = ensure_chain_matches_contract(expected_genesis_hash, GENESIS_HASH);

        // Then
        assert_eq!(result.is_ok(), accepted);
    }
}
