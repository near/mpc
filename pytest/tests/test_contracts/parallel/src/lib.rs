use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env, near_bindgen, serde_json, AccountId, Gas, NearToken, Promise};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize)]
pub struct SignArgs {
    pub request: SignRequest,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub struct TestContract;

#[near_bindgen]
impl TestContract {
    pub fn make_parallel_sign_calls(
        &self,
        target_contract: AccountId,
        num_calls: u64,
        seed: u64,
    ) -> Promise {
        // Construct `num_calls`-many sign function call promises
        let mut promises = (0..num_calls)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(format!("{seed}-{i}").as_str());
                let args = SignArgs {
                    request: SignRequest {
                        payload: hasher.finalize().into(),
                        path: "".to_string(),
                        key_version: 0,
                    },
                };
                Promise::new(target_contract.clone()).function_call(
                    "sign".to_string(),
                    serde_json::to_vec(&args).unwrap(),
                    NearToken::from_yoctonear(1),
                    Gas::from_tgas(50),
                )
            })
            .collect::<Vec<_>>();

        // Combine the calls using promise::and
        promises.reverse();
        let mut combined_promise = promises.pop().unwrap();
        while !promises.is_empty() {
            combined_promise = combined_promise.and(promises.pop().unwrap());
        }

        // Attach a callback to log the final results
        combined_promise.then(Promise::new(env::current_account_id()).function_call(
            "handle_results".to_string(),
            vec![],
            NearToken::from_near(0),
            Gas::from_tgas(30),
        ))
    }

    #[private]
    pub fn handle_results(&self) -> u64 {
        let num_calls = env::promise_results_count();
        env::log_str(format!("{num_calls} parallel calls completed!").as_str());
        for i in 0..num_calls {
            let result = env::promise_result(i);
            env::log_str(&format!("sign #{i}: {:?}", result));
        }
        num_calls
    }
}
