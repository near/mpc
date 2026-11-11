use crate::MpcContract;
use crate::api::test_utils::{must_get_attested_signer_key, participant_account_ids};
use crate::tee::test_utils::Environment;
use k256::ecdsa::SigningKey;
use k256::{Secp256k1, elliptic_curve};
use near_account_id::AccountId;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
#[cfg(feature = "foreign-tx-v2")]
use near_mpc_contract_interface::events::{
    MPC_CONTRACT_EVENT_STANDARD, VerifyForeignTxV2YieldCreated,
};
use near_mpc_contract_interface::types as dtos;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use std::collections::BTreeSet;

/// Votes `chain` into the on-chain RPC whitelist with the signing threshold of participants.
pub(super) fn whitelist_chain(contract: &mut MpcContract, chain: dtos::ForeignChain) {
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

pub(super) fn register_foreign_chains_config_for(
    contract: &mut MpcContract,
    account_id: &AccountId,
    chains: impl IntoIterator<Item = dtos::ForeignChain>,
) {
    let foreign_chains_config: dtos::ForeignChainsConfig =
        chains.into_iter().collect::<BTreeSet<_>>().into();
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
    env.set_pk(must_get_attested_signer_key(contract, &tls_key));
    contract
        .register_foreign_chains_config(foreign_chains_config)
        .expect("register should succeed");
}

/// Whitelists the chains and registers them for all participants, making them available.
pub(super) fn make_chains_available(
    contract: &mut MpcContract,
    chains: impl IntoIterator<Item = dtos::ForeignChain>,
) {
    let chains: Vec<_> = chains.into_iter().collect();
    for chain in &chains {
        whitelist_chain(contract, *chain);
    }
    for account_id in participant_account_ids(contract) {
        register_foreign_chains_config_for(contract, &account_id, chains.iter().copied());
    }
}

/// Signs `payload_hash` with a secp256k1 root secret key, as the MPC network does.
pub(crate) fn sign_payload_hash(
    secret_key: &k256::Scalar,
    payload_hash: &dtos::Hash256,
) -> dtos::SignatureResponse {
    let secret_key: elliptic_curve::SecretKey<Secp256k1> =
        elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
    let signing_key = SigningKey::from_bytes(&secret_key.to_bytes()).unwrap();
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&payload_hash.0)
        .unwrap();
    dtos::SignatureResponse::Secp256k1(dtos::K256Signature::from_ecdsa_recoverable(
        &signature,
        recovery_id,
    ))
}

#[cfg(feature = "foreign-tx-v2")]
pub(crate) fn bitcoin_request_v2() -> dtos::VerifyForeignTransactionRequestV2 {
    dtos::VerifyForeignTransactionRequestV2 {
        request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: [7u8; 32].into(),
            confirmations: 2.into(),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: dtos::DomainId::default(),
        expected_values: vec![dtos::ExtractedValue::BitcoinExtractedValue(
            dtos::BitcoinExtractedValue::BlockHash([42u8; 32].into()),
        )],
    }
}

/// The yield ids of the [`VerifyForeignTxV2YieldCreated`] events logged so far.
#[cfg(feature = "foreign-tx-v2")]
pub(crate) fn announced_yield_ids() -> Vec<dtos::YieldId> {
    const EVENT_JSON_PREFIX: &str = "EVENT_JSON:";
    near_sdk::test_utils::get_logs()
        .iter()
        .filter_map(|line| line.strip_prefix(EVENT_JSON_PREFIX))
        .map(|json| serde_json::from_str::<serde_json::Value>(json).unwrap())
        .filter(|event| {
            event["standard"] == MPC_CONTRACT_EVENT_STANDARD
                && event["event"] == VerifyForeignTxV2YieldCreated::EVENT
                && event["version"] == VerifyForeignTxV2YieldCreated::VERSION
        })
        .map(|event| {
            serde_json::from_value::<VerifyForeignTxV2YieldCreated>(event["data"].clone())
                .unwrap()
                .yield_id
        })
        .collect()
}
