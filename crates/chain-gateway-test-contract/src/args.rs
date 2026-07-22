use super::consts::{
    PRIVATE_SET, PRIVATE_SET_ARGS_GAS, SET_VALUE, SET_VALUE_GAS, SET_VALUE_IN_PROMISE,
    SET_VALUE_IN_PROMISE_GAS, SPAWN_PROMISE_WITH_CALLBACK, SPAWN_PROMISE_WITH_CALLBACK_GAS,
};

use near_contract_transport::{FunctionCallArgs, NearToken};

pub fn make_set_value_args(value: &str) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: SET_VALUE.to_string(),
        args: serde_json::to_vec(&serde_json::json!({ "value": value })).unwrap(),
        deposit: NearToken::from_near(0),
        gas: SET_VALUE_GAS,
    }
}

pub fn make_private_set_args(value: &str, succeeds: bool) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: PRIVATE_SET.to_string(),
        args: serde_json::to_vec(&serde_json::json!({ "value": value, "succeeds": succeeds }))
            .unwrap(),
        deposit: NearToken::from_near(0),
        gas: PRIVATE_SET_ARGS_GAS,
    }
}

pub fn make_set_value_in_promise_args(value: &str, return_error: bool) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: SET_VALUE_IN_PROMISE.to_string(),
        args: serde_json::to_vec(
            &serde_json::json!({ "value": value, "return_error": return_error }),
        )
        .unwrap(),
        deposit: NearToken::from_near(0),
        gas: SET_VALUE_IN_PROMISE_GAS,
    }
}

pub fn make_spawn_promise_in_callback_args(
    successfully_spawn_promise: bool,
    end_marker: &str,
) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: SPAWN_PROMISE_WITH_CALLBACK.to_string(),
        args: serde_json::to_vec(
            &serde_json::json!({ "successfully_spawn_promise": successfully_spawn_promise, "end_marker": end_marker }),
        )
        .unwrap(),
        deposit: NearToken::from_near(0),
        gas: SPAWN_PROMISE_WITH_CALLBACK_GAS,
    }
}
