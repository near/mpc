use std::time::Duration;

use super::common::localnet::Localnet;
use crate::common::{accounts::TestAccount, localnet::LocalnetBuilder};
use chain_gateway::{
    Gas,
    event_subscriber::{
        block_events::{
            BlockEventId, BlockUpdate, EventData, ExecutorFunctionCallSuccessWithPromiseData,
            ReceiverFunctionCallData,
        },
        subscriber::{BlockEventFilter, BlockEventSubscriber},
    },
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::{SubmitFunctionCall, TransactionSigner},
};
use chain_gateway_test_contract::{
    args::{
        Call, make_private_set_args, make_set_value_in_promise_args,
        make_spawn_promise_in_callback_args,
    },
    consts::{PRIVATE_SET, SET_VALUE_IN_PROMISE, VIEW_VALUE},
};
use rstest::rstest;

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
struct ExecutorFunctionCallTest {
    test_account: TestAccount,
    contract_id: near_account_id::AccountId,
    localnet: Localnet,
    receiver: tokio::sync::mpsc::Receiver<BlockUpdate>,
    set_value_in_promise_event_id: BlockEventId,
}

async fn setup_executor_function_call_filter() -> ExecutorFunctionCallTest {
    let contract_id: near_account_id::AccountId = "test-contract.near".parse().unwrap();
    let mut subscriber = BlockEventSubscriber::new(1);
    let set_value_in_promise_event_id =
        subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
            transaction_outcome_executor_id: contract_id.clone(),
            method_name: SET_VALUE_IN_PROMISE.to_string(),
        });

    let localnet = LocalnetBuilder::new().with_contract_id(contract_id.clone());
    let mut localnet = localnet
        .with_test_account("test-subscriber-sender.near".parse().unwrap())
        .with_event_subscriber(subscriber)
        .build()
        .await;
    let test_account = localnet.take_test_account();
    let receiver = localnet.take_block_update_receiver();
    ExecutorFunctionCallTest {
        test_account,
        contract_id,
        localnet,
        receiver,
        set_value_in_promise_event_id,
    }
}

/// Spins up a two-node localnet where the observer is started with a
/// `BlockEventSubscriber` filtering for executor function calls.
/// Ensures happy path: successful calls are tracked.
#[tokio::test]
async fn test_event_subscriber_executor_function_call_success_success_calls_are_tracked() {
    // Given: A subscription for tracking executions on contract_id.[`SET_VALUE_IN_PROMISE`]
    let ExecutorFunctionCallTest {
        test_account,
        contract_id,
        localnet,
        mut receiver,
        set_value_in_promise_event_id,
    } = setup_executor_function_call_filter().await;
    let observer_gw = &localnet.observer.chain_gateway;

    // When: A transaction returning a promise succeeds
    let Call {
        method, args, gas, ..
    } = make_set_value_in_promise_args("succeeds", false);

    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id,
            method,
            args.clone(),
            Gas::from_teragas(gas.into()),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let events = tokio::time::timeout(EVENT_TIMEOUT, async move {
        while let Some(BlockUpdate { events, .. }) = receiver.recv().await {
            if !events.is_empty() {
                return Some(events);
            }
        }
        None
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(events.len(), 1);

    let matched = events
        .iter()
        .find(|e| e.id == set_value_in_promise_event_id)
        .expect("expected executor event");

    let EventData::ExecutorFunctionCallSuccessWithPromise(
        ExecutorFunctionCallSuccessWithPromiseData {
            ref predecessor_id,
            ref args_raw,
            ..
        },
    ) = matched.event_data
    else {
        panic!("expected ExecutorFunctionCallSuccessWithPromise");
    };

    assert_eq!(
        *predecessor_id, test_account.account_id,
        "predecessor_id should match user account"
    );
    assert_eq!(*args_raw, args, "args must match");

    localnet.shutdown().await;
}

/// Ensures failure path: if spawning the promise fails, no executor event is logged.
#[tokio::test]
async fn test_event_subscriber_executor_function_call_success_failure_calls_are_ignored() {
    // Given: A subscription for tracking executions on contract_id.[`SET_VALUE_IN_PROMISE`]
    let ExecutorFunctionCallTest {
        test_account,
        contract_id,
        localnet,
        mut receiver,
        set_value_in_promise_event_id: _,
    } = setup_executor_function_call_filter().await;
    let observer_gw = &localnet.observer.chain_gateway;

    // When:
    // A transaction calls contract.SET_VALUE_IN_PROMISE but the spawned promise fails.
    // Add a backmarker to not wait indefinitely or be subject to race conditions.
    let end_marker: &str = "if you read this, you can be sure that the spawned promise has failed";

    let Call {
        method, args, gas, ..
    } = make_spawn_promise_in_callback_args(false, end_marker);
    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id.clone(),
            method,
            args,
            Gas::from_teragas(gas.into()),
        )
        .await
        .unwrap();

    let mut watch_value = observer_gw
        .subscribe_to_contract_method::<String>(contract_id, VIEW_VALUE)
        .await;

    loop {
        if watch_value
            .latest()
            .expect("we don't expect an error")
            .value
            == end_marker
        {
            break;
        }
        tokio::time::timeout(EVENT_TIMEOUT, watch_value.changed())
            .await
            .unwrap()
            .unwrap();
    }

    drop(watch_value);
    // close the localnet, such that we no longer get events
    localnet.shutdown().await;

    // Then: Ensure we didin' receive any events
    tokio::time::timeout(EVENT_TIMEOUT, async move {
        while let Some(BlockUpdate { events, .. }) = receiver.recv().await {
            assert!(events.is_empty(), "did not expect logged events");
        }
    })
    .await
    .unwrap();
}

struct ReceiverFunctionCallTest {
    test_account: TestAccount,
    contract_id: near_account_id::AccountId,
    contract_signer: TransactionSigner,
    localnet: Localnet,
    receiver: tokio::sync::mpsc::Receiver<BlockUpdate>,
    private_set_event_id: BlockEventId,
}

async fn setup_receiver_function_call_filter() -> ReceiverFunctionCallTest {
    let contract_id: near_account_id::AccountId = "test-contract.near".parse().unwrap();
    let mut subscriber = BlockEventSubscriber::new(1);
    let private_set_event_id = subscriber.subscribe(BlockEventFilter::ReceiverFunctionCall {
        receipt_receiver_id: contract_id.clone(),
        method_name: PRIVATE_SET.to_string(),
    });

    let mut localnet = LocalnetBuilder::new()
        .with_contract_id(contract_id.clone())
        .with_test_account("test-subscriber-sender.near".parse().unwrap())
        .with_event_subscriber(subscriber)
        .build()
        .await;
    let contract_signer =
        TransactionSigner::from_key(contract_id.clone(), localnet.contract.signing_key.clone());
    let receiver = localnet.take_block_update_receiver();
    let test_account = localnet.take_test_account();
    ReceiverFunctionCallTest {
        test_account,
        contract_id,
        contract_signer,
        localnet,
        receiver,
        private_set_event_id,
    }
}

/// Ensures `ReceiverFunctionCall` registers for private methods that return success.
#[tokio::test]
#[rstest]
#[case::successful_calls_will_be_logged(true)]
#[case::failed_calls_will_be_logged(false)]
async fn test_event_subscriber_receiver(#[case] expect_success: bool) {
    // Given: A subscription for tracking calls to the private contract_id.PRIVATE_SET
    let ReceiverFunctionCallTest {
        test_account: _,
        contract_id,
        contract_signer,
        localnet,
        mut receiver,
        private_set_event_id,
    } = setup_receiver_function_call_filter().await;
    let observer_gw = &localnet.observer.chain_gateway;

    // When: the contract calls itself:
    let Call {
        method,
        args,
        deposit: _,
        gas,
    } = make_private_set_args("maybe it works, maybe it doesn't", expect_success);

    observer_gw
        .submit_function_call_tx(
            &contract_signer,
            contract_id,
            method,
            args,
            Gas::from_teragas(gas.into()),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let events = tokio::time::timeout(EVENT_TIMEOUT, async move {
        while let Some(BlockUpdate { events, .. }) = receiver.recv().await {
            if !events.is_empty() {
                return Some(events);
            }
        }
        None
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(events.len(), 1);

    let matched = events
        .iter()
        .find(|e| e.id == private_set_event_id)
        .expect("expected executor event");

    let EventData::ReceiverFunctionCall(ReceiverFunctionCallData { is_success, .. }) =
        matched.event_data
    else {
        panic!("expected ReceiverFunctionCall");
    };
    assert_eq!(is_success, expect_success);

    localnet.shutdown().await;
}

/// Ensures `ReceiverFunctionCall` for private methods called by non-contract
/// are registered but have an error (NEAR rejects: predecessor != contract).
#[tokio::test]
async fn test_event_subscriber_receiver_error_if_non_private_call() {
    // Given: A subscription for tracking calls to the private contract_id.PRIVATE_SET
    let ReceiverFunctionCallTest {
        test_account,
        contract_id,
        contract_signer: _,
        localnet,
        mut receiver,
        private_set_event_id,
    } = setup_receiver_function_call_filter().await;
    let observer_gw = &localnet.observer.chain_gateway;

    // When: other than the contract calls it:
    let Call {
        method,
        args,
        deposit: _,
        gas,
    } = make_private_set_args("this will fail", true);

    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id,
            method,
            args,
            Gas::from_teragas(gas.into()),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let events = tokio::time::timeout(EVENT_TIMEOUT, async move {
        while let Some(BlockUpdate { events, .. }) = receiver.recv().await {
            if !events.is_empty() {
                return Some(events);
            }
        }
        None
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(events.len(), 1);

    let matched = events
        .iter()
        .find(|e| e.id == private_set_event_id)
        .expect("expected executor event");

    let EventData::ReceiverFunctionCall(ReceiverFunctionCallData { is_success, .. }) =
        matched.event_data
    else {
        panic!("expected ReceiverFunctionCall");
    };
    assert!(!is_success);

    localnet.shutdown().await;
}
