use std::collections::BTreeMap;

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::Serialize;
use near_sdk::{env, near_bindgen, serde_json, AccountId, Gas, NearToken, Promise, PromiseResult};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Payload {
    Ecdsa(String),
    Eddsa(String),
}
#[derive(Serialize)]
pub struct SignRequest {
    pub path: String,
    pub payload_v2: Option<Payload>,
    pub domain_id: Option<u64>,
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
        ecdsa_calls_by_domain: BTreeMap<u64, u64>,
        eddsa_calls_by_domain: BTreeMap<u64, u64>,
        seed: u64,
    ) -> Promise {
        fn build_calls<F>(
            target_contract: &AccountId,
            domain_map: &BTreeMap<u64, u64>,
            seed: u64,
            payload_builder: &F,
        ) -> Vec<Promise>
        where
            F: Fn(String) -> Payload,
        {
            domain_map
                .iter()
                .flat_map(|(domain_id, num_calls)| {
                    (0..*num_calls).map(move |i| {
                        let mut hasher = Sha256::new();
                        hasher.update(format!("{seed}-{i}").as_str());
                        let hex_payload = hex::encode(hasher.finalize());

                        let args = SignArgs {
                            request: SignRequest {
                                payload_v2: Some(payload_builder(hex_payload)),
                                path: "".to_string(),
                                domain_id: Some(*domain_id), // assuming DomainId is Copy
                            },
                        };

                        Promise::new(target_contract.clone()).function_call(
                            "sign".to_string(),
                            serde_json::to_vec(&args).unwrap(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(30),
                        )
                    })
                })
                .collect()
        }

        let mut promises = Vec::new();
        promises.extend(build_calls(
            &target_contract,
            &ecdsa_calls_by_domain,
            seed,
            &|hex| Payload::Ecdsa(hex),
        ));
        promises.extend(build_calls(
            &target_contract,
            &eddsa_calls_by_domain,
            seed + 1_000_000, // tweak seed offset to avoid collision if needed
            &|hex| Payload::Eddsa(hex),
        ));

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
            Gas::from_tgas(10),
        ))
    }

    #[private]
    pub fn handle_results(&self) -> u64 {
        let num_calls = env::promise_results_count();
        env::log_str(format!("{num_calls} parallel calls completed!").as_str());
        for i in 0..num_calls {
            let result = env::promise_result(i);
            env::log_str(&format!("sign #{i}: {:?}", result));
            assert!(matches!(result, PromiseResult::Successful(_)));
        }
        num_calls
    }
}
