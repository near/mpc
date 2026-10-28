use anyhow::ensure;
use near_account_id::AccountId;
use near_indexer::near_primitives::hash::CryptoHash;

struct ProductionChain {
    chain_id: &'static str,
    genesis_hash: &'static str,
}

const MAINNET: ProductionChain = ProductionChain {
    chain_id: "mainnet",
    genesis_hash: "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H",
};

const TESTNET: ProductionChain = ProductionChain {
    chain_id: "testnet",
    genesis_hash: "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b",
};

fn production_chain(contract_id: &AccountId) -> Option<ProductionChain> {
    match contract_id.as_str() {
        "v1.signer" => Some(MAINNET),
        "v1.signer-prod.testnet" => Some(TESTNET),
        _ => None,
    }
}

/// Refuses to follow any chain but the one a production contract is deployed on.
///
/// The launcher compose binds a CVM's disk sealing key to the contract account id but not to
/// a chain, so a node configured for a production contract pins the chain itself. Contracts
/// outside production are not pinned.
pub fn ensure_chain_matches_contract(
    contract_id: &AccountId,
    chain_id: &str,
    genesis_hash: CryptoHash,
) -> anyhow::Result<()> {
    let Some(ProductionChain {
        chain_id: expected_chain_id,
        genesis_hash: expected_genesis_hash,
    }) = production_chain(contract_id)
    else {
        return Ok(());
    };
    ensure!(
        chain_id == expected_chain_id && genesis_hash.to_string() == expected_genesis_hash,
        "contract {contract_id} lives on {expected_chain_id} (genesis {expected_genesis_hash}), \
         but this node follows {chain_id} (genesis {genesis_hash})"
    );
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check(contract_id: &str, chain_id: &str, genesis_hash: &str) -> anyhow::Result<()> {
        ensure_chain_matches_contract(
            &contract_id.parse().unwrap(),
            chain_id,
            genesis_hash.parse().unwrap(),
        )
    }

    #[rstest]
    #[case::mainnet("v1.signer", MAINNET)]
    #[case::testnet("v1.signer-prod.testnet", TESTNET)]
    fn ensure_chain_matches_contract__should_accept_the_chain_the_contract_lives_on(
        #[case] contract_id: &str,
        #[case] chain: ProductionChain,
    ) {
        // When / Then
        check(contract_id, chain.chain_id, chain.genesis_hash).unwrap();
    }

    #[rstest]
    #[case::other_chain_id(TESTNET.chain_id, MAINNET.genesis_hash)]
    #[case::other_genesis(MAINNET.chain_id, TESTNET.genesis_hash)]
    fn ensure_chain_matches_contract__should_reject_any_other_chain(
        #[case] chain_id: &str,
        #[case] genesis_hash: &str,
    ) {
        // When / Then
        check("v1.signer", chain_id, genesis_hash).unwrap_err();
    }

    #[test]
    fn ensure_chain_matches_contract__should_not_pin_contracts_outside_production() {
        // When / Then
        check("mpc.sandbox", "sandbox", TESTNET.genesis_hash).unwrap();
    }
}
