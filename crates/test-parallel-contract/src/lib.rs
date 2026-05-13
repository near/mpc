#![expect(
    clippy::too_many_arguments,
    reason = "make_parallel_sign_calls takes four per-scheme call maps plus seed and unique_payloads; refactoring to a single args struct is a deferred cleanup"
)]

use elliptic_curve::group::Group;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, CKDAppPublicKey, CKDRequestArgs, DomainId, Payload, SignRequestArgs,
};
use near_sdk::serde::Serialize;
use near_sdk::{env, near, serde_json, AccountId, Gas, NearToken, Promise};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct SignArgs {
    pub request: SignRequestArgs,
}

#[derive(Serialize)]
struct CKDArgs {
    pub request: CKDRequestArgs,
}

pub fn generate_app_public_key(seed: u64) -> CKDAppPublicKey {
    let x = blstrs::Scalar::from(seed);
    let big_x = blstrs::G1Projective::generator() * x;
    CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(&big_x))
}

#[near(contract_state)]
#[derive(Default)]
pub struct TestContract;

#[near]
impl TestContract {
    pub fn make_parallel_sign_calls(
        &self,
        target_contract: AccountId,
        ecdsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
        eddsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
        ckd_calls_by_domain: Option<BTreeMap<u64, u64>>,
        robust_ecdsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
        seed: u64,
        unique_payloads: bool,
    ) -> Promise {
        fn build_signature_calls<F>(
            target_contract: &AccountId,
            domain_map: &BTreeMap<u64, u64>,
            seed: u64,
            unique_payloads: bool,
            payload_builder: &F,
        ) -> Vec<Promise>
        where
            F: Fn([u8; 32]) -> Payload,
        {
            domain_map
                .iter()
                .flat_map(|(domain_id, num_calls)| {
                    (0..*num_calls).map(move |i| {
                        let mut hasher = Sha256::new();
                        let payload_input = if unique_payloads {
                            format!("{seed}-{i}")
                        } else {
                            format!("{seed}")
                        };
                        hasher.update(payload_input.as_str());
                        let payload_bytes: [u8; 32] = hasher.finalize().into();

                        let args = SignArgs {
                            request: SignRequestArgs {
                                payload: payload_builder(payload_bytes),
                                path: "".to_string(),
                                domain_id: DomainId(*domain_id),
                            },
                        };

                        Promise::new(target_contract.clone()).function_call(
                            method_names::SIGN.to_string(),
                            serde_json::to_vec(&args).unwrap(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(15),
                        )
                    })
                })
                .collect()
        }
        fn build_ckd_calls(
            target_contract: &AccountId,
            domain_map: &BTreeMap<u64, u64>,
            seed: u64,
            unique_payloads: bool,
        ) -> Vec<Promise> {
            domain_map
                .iter()
                .flat_map(|(domain_id, num_calls)| {
                    (0..*num_calls).map(move |i| {
                        let key_seed = if unique_payloads {
                            seed + i + 2
                        } else {
                            seed + 2
                        };
                        let args = CKDArgs {
                            request: CKDRequestArgs {
                                derivation_path: "".to_string(),
                                domain_id: DomainId(*domain_id),
                                app_public_key: generate_app_public_key(key_seed),
                            },
                        };

                        Promise::new(target_contract.clone()).function_call(
                            method_names::REQUEST_APP_PRIVATE_KEY.to_string(),
                            serde_json::to_vec(&args).unwrap(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(30),
                        )
                    })
                })
                .collect()
        }

        let mut promises = Vec::new();
        if let Some(ecdsa_calls_by_domain) = ecdsa_calls_by_domain {
            promises.extend(build_signature_calls(
                &target_contract,
                &ecdsa_calls_by_domain,
                seed,
                unique_payloads,
                &|bytes| Payload::Ecdsa(bytes.into()),
            ));
        };

        if let Some(eddsa_calls_by_domain) = eddsa_calls_by_domain {
            promises.extend(build_signature_calls(
                &target_contract,
                &eddsa_calls_by_domain,
                seed + 1_000_000, // tweak seed offset to avoid collision if needed
                unique_payloads,
                &|bytes| Payload::Eddsa(bytes.into()),
            ));
        };
        if let Some(ckd_calls_by_domain) = ckd_calls_by_domain {
            promises.extend(build_ckd_calls(
                &target_contract,
                &ckd_calls_by_domain,
                seed,
                unique_payloads,
            ));
        };
        if let Some(robust_ecdsa_calls_by_domain) = robust_ecdsa_calls_by_domain {
            promises.extend(build_signature_calls(
                &target_contract,
                &robust_ecdsa_calls_by_domain,
                seed + 2_000_000,
                unique_payloads,
                &|bytes| Payload::Ecdsa(bytes.into()),
            ));
        };

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
            let result = env::promise_result_checked(i, 500);
            env::log_str(&format!("sign #{i}: {:?}", result));
            assert_matches::assert_matches!(result, Ok(_));
        }
        num_calls
    }
}
