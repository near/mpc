use std::time::Duration;

use super::common::localnet::Localnet;
use crate::common::{accounts::TestAccount, localnet::LocalnetBuilder};
use chain_gateway::{
    event_subscriber::{
        block_events::{
            BlockEventId, BlockUpdate, EventData, ExecutorFunctionCallSuccessWithPromiseData,
            ReceiverFunctionCallData,
        },
        subscriber::{BlockEventSubscription, BlockEventSubscriptions},
    },
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::{SubmitFunctionCall, TransactionSigner},
};
use chain_gateway_test_contract::{
    args::{
        make_private_set_args, make_set_value_in_promise_args, make_spawn_promise_in_callback_args,
    },
    consts::{PRIVATE_SET, SET_VALUE_IN_PROMISE, VIEW_VALUE},
};
use rstest::rstest;

// Generous: the gateway now waits for the node to catch up to its peers before
// streaming (see `wait_for_full_sync`), which delays the first block update on a
// loaded CI box.
const EVENT_TIMEOUT: Duration = Duration::from_secs(30);

async fn must_recv_block_update(
    receiver: &mut tokio::sync::mpsc::Receiver<BlockUpdate>,
) -> BlockUpdate {
    tokio::time::timeout(EVENT_TIMEOUT, receiver.recv())
        .await
        .expect("expected a block update before timeout")
        .expect("expected a block update, channel closed")
}

struct ExecutorFunctionCallTest {
    test_account: TestAccount,
    contract_id: near_account_id::AccountId,
    localnet: Localnet,
    receiver: tokio::sync::mpsc::Receiver<BlockUpdate>,
    set_value_in_promise_event_id: BlockEventId,
}

async fn setup_executor_function_call_filter() -> ExecutorFunctionCallTest {
    let contract_id: near_account_id::AccountId = "test-contract.near".parse().unwrap();
    let mut subscriber = BlockEventSubscriptions::new(1);
    let set_value_in_promise_event_id = subscriber.subscribe(
        BlockEventSubscription::ExecutorFunctionCallSuccessWithPromise {
            transaction_outcome_executor_id: contract_id.clone(),
            method_name: SET_VALUE_IN_PROMISE.to_string(),
        },
    );

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
/// `BlockEventSubscriptions` filtering for executor function calls.
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
    let call = make_set_value_in_promise_args("succeeds", false);

    observer_gw
        .submit_function_call_tx(&test_account.signer, contract_id, call.clone())
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = must_recv_block_update(&mut receiver).await;

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
    assert_eq!(*args_raw, call.args, "args must match");

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

    let call = make_spawn_promise_in_callback_args(false, end_marker);
    observer_gw
        .submit_function_call_tx(&test_account.signer, contract_id.clone(), call)
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

    // Then: shutdown closes the channel; anything buffered would be an unexpected event.
    receiver
        .try_recv()
        .expect_err("expected channel to be empty");
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
    setup_receiver_function_call_filter_with_buffer(1).await
}

async fn setup_receiver_function_call_filter_with_buffer(
    buffer_size: usize,
) -> ReceiverFunctionCallTest {
    let contract_id: near_account_id::AccountId = "test-contract.near".parse().unwrap();
    let mut subscriber = BlockEventSubscriptions::new(buffer_size);
    let private_set_event_id = subscriber.subscribe(BlockEventSubscription::ReceiverFunctionCall {
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
    let call = make_private_set_args("maybe it works, maybe it doesn't", expect_success);

    observer_gw
        .submit_function_call_tx(&contract_signer, contract_id, call)
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = must_recv_block_update(&mut receiver).await;

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
    let call = make_private_set_args("this will fail", true);

    observer_gw
        .submit_function_call_tx(&test_account.signer, contract_id, call)
        .await
        .unwrap();

    // Then: expect a matching block update
    let BlockUpdate { events, .. } = must_recv_block_update(&mut receiver).await;

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

/// Two `private_set` txs are submitted sequentially, with a `view_value` sync
/// between them to force the receipts into distinct blocks.
/// If the buffer fits both updates, we expect to receive both block events.
/// If the buffer does not fit both updates, we expect the latest updates to be dropped.
#[rstest]
#[case::buffer_fits_both_updates(2, 2)]
#[case::buffer_drops_second_update_when_full(1, 1)]
#[tokio::test]
async fn test_event_subscriber_channel_buffer_handles_backpressure(
    #[case] buffer_size: usize,
    #[case] expected_received: usize,
) {
    let ReceiverFunctionCallTest {
        test_account: _,
        contract_id,
        contract_signer,
        localnet,
        mut receiver,
        private_set_event_id: _,
    } = setup_receiver_function_call_filter_with_buffer(buffer_size).await;
    let observer_gw = &localnet.observer.chain_gateway;

    let mut watch_value = observer_gw
        .subscribe_to_contract_method::<String>(contract_id.clone(), VIEW_VALUE)
        .await;

    for target in ["first", "second"] {
        let call = make_private_set_args(target, true);
        observer_gw
            .submit_function_call_tx(&contract_signer, contract_id.clone(), call)
            .await
            .unwrap();
        loop {
            if watch_value
                .latest()
                .expect("we don't expect an error")
                .value
                == target
            {
                break;
            }
            tokio::time::timeout(EVENT_TIMEOUT, watch_value.changed())
                .await
                .unwrap()
                .unwrap();
        }
    }
    drop(watch_value);

    for _ in 0..expected_received {
        must_recv_block_update(&mut receiver).await;
    }
    receiver
        .try_recv()
        .expect_err("expected no further updates");

    localnet.shutdown().await;
}

/// Ensures a `BlockStatusHandle` from a `BlockUpdate` eventually reports finality.
///
/// Synchronisation: the state viewer only reports finalised contract state, so once
/// it sees the value change, the block whose handle we hold is necessarily final too.
#[tokio::test]
async fn test_block_status_handle_becomes_final() {
    // Given
    let ExecutorFunctionCallTest {
        test_account,
        contract_id,
        localnet,
        mut receiver,
        ..
    } = setup_executor_function_call_filter().await;
    let observer_gw = &localnet.observer.chain_gateway;

    // When: one tx that triggers an event and changes contract state.
    let target_value = "becomes-final";
    let call = make_set_value_in_promise_args(target_value, false);
    observer_gw
        .submit_function_call_tx(&test_account.signer, contract_id.clone(), call)
        .await
        .unwrap();

    let BlockUpdate { status, .. } = must_recv_block_update(&mut receiver).await;

    // Sync on the state viewer observing the finalised state change.
    let mut watch_value = observer_gw
        .subscribe_to_contract_method::<String>(contract_id, VIEW_VALUE)
        .await;
    loop {
        if watch_value
            .latest()
            .expect("we don't expect an error")
            .value
            == target_value
        {
            break;
        }
        tokio::time::timeout(EVENT_TIMEOUT, watch_value.changed())
            .await
            .expect("we expect value to change due to our function call")
            .unwrap();
    }
    drop(watch_value);

    // Then: the handle reports its block as final. The state viewer can see
    // finality slightly before the streamer's tracker registers it (independent
    // polling paths), so allow a short window for the tracker to catch up.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while status.is_final() != Some(true) {
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "expected the block to be final once the state viewer confirmed the change; is_final={:?}",
                status.is_final(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    localnet.shutdown().await;
}
