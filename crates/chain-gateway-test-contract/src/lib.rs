pub mod args;
pub mod consts;

use args::{Call, make_private_set_args, make_set_value_in_promise_args};
use consts::DEFAULT_VALUE;

use near_sdk::{
    Gas, Promise,
    env::{self, log_str},
    near,
};

pub fn compiled_wasm() -> &'static [u8] {
    include_bytes!("../res/chain_gateway_test_contract.wasm")
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
    pub fn set_value_in_promise(
        &mut self,
        value: String,
        return_error: bool,
    ) -> Result<Promise, String> {
        if return_error {
            Err("computer says no".to_string())
        } else {
            let Call {
                method,
                args,
                deposit,
                tera_gas,
            } = make_private_set_args(&value, true);
            Ok(Promise::new(env::current_account_id()).function_call(
                method,
                args,
                deposit,
                Gas::from_tgas(tera_gas),
            ))
        }
    }

    /// Chains two promises: first calls [`set_value_in_promise`](Self::set_value_in_promise)
    /// (which may fail based on `successfully_spawn_promise`), then a callback that writes
    /// `end_marker` via [`private_set`](Self::private_set). The callback acts as a
    /// synchronization marker so tests can poll [`view_value`](Self::view_value) to know the
    /// full chain completed.
    pub fn spawn_promise_with_callback(
        successfully_spawn_promise: bool,
        end_marker: String,
    ) -> Promise {
        // spawn first promise
        let Call {
            method,
            args,
            deposit,
            tera_gas,
        } = make_set_value_in_promise_args("doesn't matter", !successfully_spawn_promise);
        let promise = Promise::new(env::current_account_id()).function_call(
            method,
            args,
            deposit,
            Gas::from_tgas(tera_gas),
        );

        // spawn callback promise to mark conclusion of first promise
        let Call {
            method,
            args,
            deposit,
            tera_gas,
        } = make_private_set_args(&end_marker, true);
        let callback = Promise::new(env::current_account_id()).function_call(
            method,
            args,
            deposit,
            Gas::from_tgas(tera_gas),
        );
        promise.then(callback)
    }

    /// Can only be called by the contract itself (via a promise).
    #[private]
    #[handle_result]
    pub fn private_set(&mut self, value: String, succeeds: bool) -> Result<(), String> {
        if succeeds {
            self.set_value(value);
            Ok(())
        } else {
            Err("intentional error for testing".to_string())
        }
    }
}
