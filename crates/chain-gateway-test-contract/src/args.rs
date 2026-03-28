use super::consts::{
    PRIVATE_SET, PRIVATE_SET_ARGS_TGAS, SET_VALUE, SET_VALUE_IN_PROMISE, SET_VALUE_IN_PROMISE_TGAS,
    SET_VALUE_TGAS, SPAWN_PROMISE_WITH_CALLBACK, SPAWN_PROMISE_WITH_CALLBACK_TGAS,
};

use near_sdk::NearToken;

pub struct Call {
    pub method: String,
    pub args: Vec<u8>,
    pub deposit: NearToken,
    pub tera_gas: u64,
}

pub fn make_set_value_args(value: &str) -> Call {
    Call {
        method: SET_VALUE.to_string(),
        args: serde_json::to_vec(&serde_json::json!({ "value": value })).unwrap(),
        deposit: NearToken::from_near(0),
        tera_gas: SET_VALUE_TGAS,
    }
}

pub fn make_private_set_args(value: &str, succeeds: bool) -> Call {
    Call {
        method: PRIVATE_SET.to_string(),
        args: serde_json::to_vec(&serde_json::json!({ "value": value, "succeeds": succeeds }))
            .unwrap(),
        deposit: NearToken::from_near(0),
        tera_gas: PRIVATE_SET_ARGS_TGAS,
    }
}

pub fn make_set_value_in_promise_args(value: &str, return_error: bool) -> Call {
    Call {
        method: SET_VALUE_IN_PROMISE.to_string(),
        args: serde_json::to_vec(
            &serde_json::json!({ "value": value, "return_error": return_error }),
        )
        .unwrap(),
        deposit: NearToken::from_near(0),
        tera_gas: SET_VALUE_IN_PROMISE_TGAS,
    }
}

pub fn make_spawn_promise_in_callback_args(
    successfully_spawn_promise: bool,
    end_marker: &str,
) -> Call {
    Call {
        method: SPAWN_PROMISE_WITH_CALLBACK.to_string(),
        args: serde_json::to_vec(
            &serde_json::json!({ "successfully_spawn_promise": successfully_spawn_promise, "end_marker": end_marker }),
        )
        .unwrap(),
        deposit: NearToken::from_near(0),
        tera_gas: SPAWN_PROMISE_WITH_CALLBACK_TGAS,
    }
}
