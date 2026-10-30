//! A typed client for the contract, and the calls the integration tests send.

use near_kit_primitives::transaction::FunctionCall;

use super::consts::{
    PRIVATE_SET_ARGS_GAS, SET_VALUE_GAS, SET_VALUE_IN_PROMISE_GAS, SPAWN_PROMISE_WITH_CALLBACK_GAS,
};

#[near_kit_primitives::contract]
pub trait TestContract {
    fn view_value(&self) -> String;
    #[call]
    fn set_value(&mut self, value: String);
    #[call]
    fn private_set(&mut self, value: String, succeeds: bool);
    #[call]
    fn set_value_in_promise(&mut self, value: String, return_error: bool);
    #[call]
    fn spawn_promise_with_callback(&mut self, successfully_spawn_promise: bool, end_marker: String);
}

pub fn make_set_value_args(value: &str) -> FunctionCall {
    TestContract::set_value(value.to_string()).gas(SET_VALUE_GAS)
}

pub fn make_private_set_args(value: &str, succeeds: bool) -> FunctionCall {
    TestContract::private_set(value.to_string(), succeeds).gas(PRIVATE_SET_ARGS_GAS)
}

pub fn make_set_value_in_promise_args(value: &str, return_error: bool) -> FunctionCall {
    TestContract::set_value_in_promise(value.to_string(), return_error)
        .gas(SET_VALUE_IN_PROMISE_GAS)
}

pub fn make_spawn_promise_in_callback_args(
    successfully_spawn_promise: bool,
    end_marker: &str,
) -> FunctionCall {
    TestContract::spawn_promise_with_callback(successfully_spawn_promise, end_marker.to_string())
        .gas(SPAWN_PROMISE_WITH_CALLBACK_GAS)
}
