use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS, mpc_contract::get_state, resharing_utils::conclude_resharing,
        sandbox_mpc_contract::SandboxMpcContract, transactions::CallMpcContract,
    },
};
use near_mpc_contract_interface::types::{
    EpochId, InitConfig, ProtocolContractState, RunningContractState,
};
use std::assert_matches;

#[tokio::test]
#[expect(non_snake_case)]
async fn trigger_key_refresh__should_reshare_onto_the_same_participants_when_due() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_init_config(InitConfig {
            key_refresh_period_seconds: Some(0),
            ..InitConfig::default()
        })
        .build()
        .await;
    let initial_state = running_state(&contract).await;
    let prospective_epoch_id = EpochId(initial_state.keyset.epoch_id.0 + 1);

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .trigger_key_refresh()
        .await
        .unwrap();
    let ProtocolContractState::Resharing(resharing_state) = get_state(&contract).await else {
        panic!("expected resharing state: {execution:#?}");
    };
    conclude_resharing(&contract, &mpc_signer_accounts, prospective_epoch_id)
        .await
        .unwrap();

    // Then
    assert_eq!(
        resharing_state.resharing_key.parameters,
        initial_state.parameters
    );
    let refreshed_state = running_state(&contract).await;
    assert_eq!(refreshed_state.keyset.epoch_id, prospective_epoch_id);
    assert_eq!(refreshed_state.parameters, initial_state.parameters);
    assert_eq!(refreshed_state.domains, initial_state.domains);
    assert_eq!(public_keys(&refreshed_state), public_keys(&initial_state));
}

#[tokio::test]
#[expect(non_snake_case)]
async fn trigger_key_refresh__should_fail_before_refresh_is_due() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .trigger_key_refresh()
        .await
        .unwrap();

    // Then
    let failure = format!("{:?}", execution.into_result().unwrap_err());
    assert!(failure.contains("Key refresh is not due"), "{failure}");
    assert_matches!(
        get_state(&contract).await,
        ProtocolContractState::Running(_)
    );
}

async fn running_state(contract: &SandboxMpcContract) -> RunningContractState {
    let ProtocolContractState::Running(state) = get_state(contract).await else {
        panic!("expected running state");
    };
    state
}

fn public_keys(state: &RunningContractState) -> Vec<String> {
    state
        .keyset
        .domains
        .iter()
        .map(|key| format!("{:?}", key.key))
        .collect()
}
