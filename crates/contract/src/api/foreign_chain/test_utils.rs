use crate::MpcContract;
use crate::api::test_utils::participant_account_ids;
use crate::tee::test_utils::Environment;
use near_account_id::AccountId;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use std::collections::BTreeSet;

/// Votes `chain` into the on-chain RPC whitelist with the signing threshold of participants.
pub(super) fn must_whitelist_chain(contract: &mut MpcContract, chain: dtos::ForeignChain) {
    let batch = NonEmptyBTreeMap::new(chain, ::test_utils::contract_types::dummy_chain_entry());
    let threshold = contract.threshold().unwrap().value() as usize;
    let participants = participant_account_ids(contract);
    assert!(
        participants.len() >= threshold,
        "need at least {threshold} participants to whitelist a chain, got {}",
        participants.len()
    );
    for account_id in participants.iter().take(threshold) {
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_update_foreign_chain_providers(batch.clone())
            .expect("vote should succeed");
    }
}

pub(super) fn must_register_foreign_chains_config_for(
    contract: &mut MpcContract,
    account_id: &AccountId,
    chains: impl IntoIterator<Item = dtos::ForeignChain>,
) {
    let foreign_chains_config: dtos::ForeignChainsConfig =
        chains.into_iter().collect::<BTreeSet<_>>().into();
    // In mock setup, account_public_key == tls_public_key.
    let tls_key = contract
        .protocol_state
        .threshold_parameters()
        .unwrap()
        .participants()
        .info(account_id)
        .expect("account must be a participant")
        .tls_public_key
        .clone();
    let mut env = Environment::new(None, Some(account_id.clone()), None);
    env.set_pk(near_sdk::PublicKey::from(tls_key));
    contract
        .register_foreign_chains_config(foreign_chains_config)
        .expect("register should succeed");
}
