use anyhow::ensure;
use near_account_id::AccountId;
use near_indexer::near_primitives::hash::CryptoHash;

const MAINNET_GENESIS_HASH: &str = "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H";
const TESTNET_GENESIS_HASH: &str = "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b";

/// The measured launcher compose binds a node to its contract account id but not to a chain, so
/// a node serving a production contract refuses to follow any other chain.
pub fn ensure_chain_matches_contract(
    contract_id: &AccountId,
    genesis_hash: CryptoHash,
) -> anyhow::Result<()> {
    let expected_genesis_hash = match contract_id.as_str() {
        "v1.signer" => MAINNET_GENESIS_HASH,
        "v1.signer-prod.testnet" => TESTNET_GENESIS_HASH,
        _ => return Ok(()),
    };
    ensure!(
        genesis_hash.to_string() == expected_genesis_hash,
        "contract {contract_id} lives on the chain with genesis {expected_genesis_hash}, \
         but this node follows the chain with genesis {genesis_hash}"
    );
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::mainnet_contract_on_mainnet("v1.signer", MAINNET_GENESIS_HASH, true)]
    #[case::testnet_contract_on_testnet("v1.signer-prod.testnet", TESTNET_GENESIS_HASH, true)]
    #[case::mainnet_contract_on_testnet("v1.signer", TESTNET_GENESIS_HASH, false)]
    #[case::other_contract_on_any_chain("mpc.sandbox", TESTNET_GENESIS_HASH, true)]
    fn ensure_chain_matches_contract__should_pin_only_production_contracts_to_their_chain(
        #[case] contract_id: &str,
        #[case] genesis_hash: &str,
        #[case] accepted: bool,
    ) {
        // When
        let result = ensure_chain_matches_contract(
            &contract_id.parse().unwrap(),
            genesis_hash.parse().unwrap(),
        );

        // Then
        assert_eq!(result.is_ok(), accepted);
    }
}
