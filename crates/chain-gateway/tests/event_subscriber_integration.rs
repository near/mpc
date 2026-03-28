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
    consts::{PRIVATE_SET, SET_VALUE_IN_PROMISE, SPAWN_PROMISE_WITH_CALLBACK, VIEW},
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
    let (localnet, test_account) =
        localnet.with_test_account("test-subscriber-sender.near".parse().unwrap());
    let mut localnet = localnet.with_event_subscriber(subscriber).build().await;
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
        method,
        args,
        tera_gas,
        ..
    } = make_set_value_in_promise_args("succeeds", false);

    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id,
            method,
            args.clone(),
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = tokio::time::timeout(EVENT_TIMEOUT, receiver.recv())
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
        method,
        args,
        tera_gas,
        ..
    } = make_spawn_promise_in_callback_args(false, end_marker);
    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id.clone(),
            method,
            args,
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    let mut watch_value = observer_gw
        .subscribe_to_contract_method::<String>(contract_id, VIEW)
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

    assert!(
        receiver.is_empty(),
        "expected no executor events for a failed call, found: {:?}",
        receiver.recv().await.unwrap()
    );

    localnet.shutdown().await;
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

    let localnet = LocalnetBuilder::new().with_contract_id(contract_id.clone());
    let (localnet, test_account) =
        localnet.with_test_account("test-subscriber-sender.near".parse().unwrap());
    let mut localnet = localnet.with_event_subscriber(subscriber).build().await;
    let contract_signer =
        TransactionSigner::from_key(contract_id.clone(), localnet.contract.signing_key.clone());
    let receiver = localnet.take_block_update_receiver();
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
        tera_gas,
    } = make_private_set_args("maybe it works, maybe it doesn't", expect_success);

    observer_gw
        .submit_function_call_tx(
            &contract_signer,
            contract_id,
            method,
            args,
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = tokio::time::timeout(EVENT_TIMEOUT, receiver.recv())
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
        tera_gas,
    } = make_private_set_args("this will fail", true);

    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id,
            method,
            args,
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = tokio::time::timeout(EVENT_TIMEOUT, receiver.recv())
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

/// Verifies that the send-timeout circuit breaker works: when the consumer does not read from the
/// channel and the buffer is full, `listen_blocks` exits with `BlockEventBufferFull` and the
/// receiver channel closes.
#[tokio::test]
async fn test_event_subscriber_backpressure_buffer_full_closes_channel() {
    // Given: subscribing to three events that fire in three different blocks
    let contract_id: near_account_id::AccountId =
        "test-backpressure-handling.near".parse().unwrap();
    let mut subscriber =
        BlockEventSubscriber::new(1).with_backpressure_timeout(Duration::from_nanos(1));
    let _ = subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
        transaction_outcome_executor_id: contract_id.clone(),
        method_name: SPAWN_PROMISE_WITH_CALLBACK.to_string(),
    });
    let _ = subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
        transaction_outcome_executor_id: contract_id.clone(),
        method_name: SET_VALUE_IN_PROMISE.to_string(),
    });
    let _ = subscriber.subscribe(BlockEventFilter::ReceiverFunctionCall {
        receipt_receiver_id: contract_id.clone(),
        method_name: PRIVATE_SET.to_string(),
    });
    let localnet = LocalnetBuilder::new().with_contract_id(contract_id.clone());
    let (localnet, test_account) =
        localnet.with_test_account("test-subscriber-sender.near".parse().unwrap());
    let mut localnet = localnet.with_event_subscriber(subscriber).build().await;
    let mut receiver = localnet.take_block_update_receiver();

    const MARKER: &str = "race condition avoided";

    // When: We call the method, leading to the promise chain
    let Call {
        method,
        args,
        deposit: _,
        tera_gas,
    } = make_spawn_promise_in_callback_args(true, MARKER);
    let observer_gw = &localnet.observer.chain_gateway;
    observer_gw
        .submit_function_call_tx(
            &test_account.signer,
            contract_id.clone(),
            method,
            args.clone(),
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    // wait for change to take effect
    let mut watch_value = observer_gw
        .subscribe_to_contract_method::<String>(contract_id, VIEW)
        .await;

    loop {
        if watch_value
            .latest()
            .expect("we don't expect an error")
            .value
            == *MARKER
        {
            break;
        }
        tokio::time::timeout(EVENT_TIMEOUT, watch_value.changed())
            .await
            .unwrap()
            .unwrap();
    }

    drop(watch_value);

    // Then: expect the sender to drop the channel and the streamer to close
    let mut received_blocks = 0u32;
    let closed = tokio::time::timeout(Duration::from_secs(30), async {
        // drain the only event that squeezed through before the timeout.
        while receiver.recv().await.is_some() {
            received_blocks += 1;
        }
    })
    .await;

    assert!(
        closed.is_ok(),
        "receiver channel should have closed (listen_blocks exited with BlockEventBufferFull)"
    );

    assert_eq!(
        received_blocks, 1,
        "buffer size was one, we only expect one block update before the stream closes"
    );

    localnet.shutdown().await;
}
