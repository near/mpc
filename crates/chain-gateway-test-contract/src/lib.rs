use near_sdk::{
    Gas, NearToken, Promise,
    env::{self, log_str},
    near,
};

pub fn compiled_wasm() -> &'static [u8] {
    include_bytes!("../res/chain_gateway_test_contract.wasm")
}

pub const DEFAULT_VALUE: &str = "hello from test";

// public view method
pub const VIEW_METHOD: &str = "view_value";

// public set method
pub const SET_VALUE: &str = "set_value";
pub const SET_VALUE_TGAS: u64 = FIVE_TGAS;

// teragas as u64. We don't use near_sdk::Gas on purpose, such that the near indexer can re-use
// these constants without depending on near_sdk.
pub const FIVE_TGAS: u64 = 5;

// methods that spawn promises
pub const SET_VALUE_IN_PROMISE: &str = "set_value_in_promise";
pub const SET_VALUE_IN_PROMISE_TGAS: u64 = SET_VALUE_TGAS + FIVE_TGAS;

pub const SPAWN_PROMISE_WITH_CALLBACK: &str = "spawn_promise_with_callback";
pub const SPAWN_PROMISE_WITH_CALLBACK_TGAS: u64 =
    SET_VALUE_IN_PROMISE_TGAS + SET_VALUE_TGAS + FIVE_TGAS;

// private method for setting value
pub const PRIVATE_SET: &str = "private_set";
pub const PRIVATE_SET_ARGS_TGAS: u64 = 5;

#[near(serializers=[json])]
pub struct PrivateSetArgs {
    pub value: String,
    pub succeeds: bool,
}

#[near(serializers=[json])]
pub struct SetValueInPromiseArgs {
    pub value: String,
    pub return_error: bool,
}

#[near(serializers=[json])]
pub struct SetValueWithMarker {
    pub successfully_spawn_promise: bool,
    pub end_marker: String,
}

#[derive(Debug)]
#[near(contract_state)]
pub struct Contract {
    stored_value: String,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            stored_value: DEFAULT_VALUE.to_string(),
        }
    }
}

#[near]
impl Contract {
    pub fn view_value(&self) -> &str {
        &self.stored_value
    }

    pub fn set_value(&mut self, value: String) {
        log_str(&format!("Setting value to: {value}"));
        self.stored_value = value;
    }

    /// Spawns a cross-contract promise to [`private_set`](Self::private_set), returning an error
    /// if `return_error` is set. Used by integration tests to verify
    /// `ExecutorFunctionCallSuccessWithPromise` event tracking.
    #[handle_result]
    pub fn set_value_in_promise(&mut self, args: SetValueInPromiseArgs) -> Result<Promise, String> {
        if args.return_error {
            Err("computer says no".to_string())
        } else {
            let private_set_args = PrivateSetArgs {
                value: args.value,
                succeeds: true,
            };
            Ok(Promise::new(env::current_account_id()).function_call(
                PRIVATE_SET.to_string(),
                serde_json::to_vec(&serde_json::json!({"args": private_set_args})).unwrap(),
                NearToken::from_near(0),
                Gas::from_tgas(PRIVATE_SET_ARGS_TGAS),
            ))
        }
    }

    /// Chains two promises: first calls [`set_value_in_promise`](Self::set_value_in_promise)
    /// (which may fail based on `successfully_spawn_promise`), then a callback that writes
    /// `end_marker` via [`private_set`](Self::private_set). The callback acts as a
    /// synchronization marker so tests can poll [`view_value`](Self::view_value) to know the
    /// full chain completed.
    pub fn spawn_promise_with_callback(args: SetValueWithMarker) -> Promise {
        let set_value_args = SetValueInPromiseArgs {
            value: "doesn't matter".to_string(),
            return_error: !args.successfully_spawn_promise,
        };
        let promise = Promise::new(env::current_account_id()).function_call(
            SET_VALUE_IN_PROMISE.to_string(),
            serde_json::to_vec(&serde_json::json!({"args": set_value_args})).unwrap(),
            NearToken::from_near(0),
            Gas::from_tgas(SET_VALUE_IN_PROMISE_TGAS),
        );
        let private_set_args = PrivateSetArgs {
            value: args.end_marker,
            succeeds: true,
        };
        let callback = Promise::new(env::current_account_id()).function_call(
            PRIVATE_SET.to_string(),
            serde_json::to_vec(&serde_json::json!({"args": private_set_args})).unwrap(),
            NearToken::from_near(0),
            Gas::from_tgas(PRIVATE_SET_ARGS_TGAS),
        );
        promise.then(callback)
    }

    /// Can only be called by the contract itself (via a promise).
    #[private]
    #[handle_result]
    pub fn private_set(&mut self, args: PrivateSetArgs) -> Result<(), String> {
        if args.succeeds {
            self.set_value(args.value);
            Ok(())
        } else {
            Err("intentional error for testing".to_string())
        }
    }
}
