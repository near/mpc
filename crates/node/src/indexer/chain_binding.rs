use anyhow::ensure;
use near_indexer::near_primitives::hash::CryptoHash;

/// Fails unless the node follows the chain whose genesis hash the measured launcher compose names.
/// A node started without the launcher has no expected genesis hash and follows any chain.
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

    const MAINNET_GENESIS_HASH: &str = "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H";
    const TESTNET_GENESIS_HASH: &str = "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b";

    #[rstest]
    #[case::same_chain(Some(MAINNET_GENESIS_HASH), MAINNET_GENESIS_HASH, true)]
    #[case::other_chain(Some(MAINNET_GENESIS_HASH), TESTNET_GENESIS_HASH, false)]
    #[case::no_expected_chain(None, TESTNET_GENESIS_HASH, true)]
    fn ensure_chain_matches_contract__should_reject_a_chain_other_than_the_expected_one(
        #[case] expected_genesis_hash: Option<&str>,
        #[case] genesis_hash: &str,
        #[case] accepted: bool,
    ) {
        // Given
        let expected_genesis_hash = expected_genesis_hash.map(|hash| hash.parse().unwrap());
        let genesis_hash: CryptoHash = genesis_hash.parse().unwrap();

        // When
        let result = ensure_chain_matches_contract(expected_genesis_hash, genesis_hash);

        // Then
        assert_eq!(result.is_ok(), accepted);
    }
}
