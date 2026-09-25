use elliptic_curve::group::Group;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, CKDAppPublicKey, CKDRequestArgs, DomainId, Payload, SignRequestArgs,
};
use near_sdk::{AccountId, Gas, NearToken, Promise, env, ext_contract, near};
use std::collections::BTreeMap;

#[ext_contract(ext_mpc_contract)]
pub trait MpcContract {
    fn sign(&mut self, request: SignRequestArgs);
    fn request_app_private_key(&mut self, request: CKDRequestArgs);
}

pub fn generate_app_public_key(seed: u64) -> CKDAppPublicKey {
    let x = blstrs::Scalar::from(seed);
    let big_x = blstrs::G1Projective::generator() * x;
    CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(&big_x))
}

/// Gas attached to each cross-contract `sign` / `verify_foreign_transaction` call this
/// contract fans out.
const SIGN_CALL_TGAS: u64 = 15;

/// Gas attached to each cross-contract `request_app_private_key` call.
const CKD_CALL_TGAS: u64 = 30;

/// Gas attached to the `handle_results` self-callback.
const HANDLE_RESULTS_TGAS: u64 = 10;

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
    ) -> Promise {
        fn build_signature_calls<F>(
            target_contract: &AccountId,
            domain_map: &BTreeMap<u64, u64>,
            seed: u64,
            payload_builder: &F,
        ) -> Vec<Promise>
        where
            F: Fn([u8; 32]) -> Payload,
        {
            domain_map
                .iter()
                .flat_map(|(domain_id, num_calls)| {
                    (0..*num_calls).map(move |i| {
                        let payload_bytes = env::sha256_array(format!("{seed}-{i}"));

                        sign_promise(
                            target_contract,
                            SignRequestArgs {
                                payload: payload_builder(payload_bytes),
                                path: "".to_string(),
                                domain_id: DomainId(*domain_id),
                            },
                        )
                    })
                })
                .collect()
        }
        fn build_ckd_calls(
            target_contract: &AccountId,
            domain_map: &BTreeMap<u64, u64>,
            seed: u64,
        ) -> Vec<Promise> {
            domain_map
                .iter()
                .flat_map(|(domain_id, num_calls)| {
                    (0..*num_calls).map(move |i| {
                        ckd_promise(
                            target_contract,
                            CKDRequestArgs {
                                derivation_path: "".to_string(),
                                domain_id: DomainId(*domain_id),
                                app_public_key: generate_app_public_key(seed + i + 2),
                            },
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
                &|bytes| Payload::Ecdsa(bytes.into()),
            ));
        };

        if let Some(eddsa_calls_by_domain) = eddsa_calls_by_domain {
            promises.extend(build_signature_calls(
                &target_contract,
                &eddsa_calls_by_domain,
                seed + 1_000_000, // tweak seed offset to avoid collision if needed
                &|bytes| Payload::Eddsa(bytes.into()),
            ));
        };
        if let Some(ckd_calls_by_domain) = ckd_calls_by_domain {
            promises.extend(build_ckd_calls(
                &target_contract,
                &ckd_calls_by_domain,
                seed,
            ));
        };
        if let Some(robust_ecdsa_calls_by_domain) = robust_ecdsa_calls_by_domain {
            promises.extend(build_signature_calls(
                &target_contract,
                &robust_ecdsa_calls_by_domain,
                seed + 2_000_000,
                &|bytes| Payload::Ecdsa(bytes.into()),
            ));
        };

        join_with_handle_results(promises)
    }

    /// Emits `count` identical `sign` cross-contract calls for `request` and resolves
    /// via `handle_results`. Used by tests exercising the duplicate-request fan-out
    /// path: the caller picks the payload (so it knows which response to produce) and
    /// the contract just clones it `count` times.
    pub fn make_duplicate_sign_calls(
        &self,
        target_contract: AccountId,
        request: SignRequestArgs,
        count: u64,
    ) -> Promise {
        let promises = (0..count)
            .map(|_| sign_promise(&target_contract, request.clone()))
            .collect();
        join_with_handle_results(promises)
    }

    /// CKD counterpart to [`Self::make_duplicate_sign_calls`].
    pub fn make_duplicate_ckd_calls(
        &self,
        target_contract: AccountId,
        request: CKDRequestArgs,
        count: u64,
    ) -> Promise {
        let promises = (0..count)
            .map(|_| ckd_promise(&target_contract, request.clone()))
            .collect();
        join_with_handle_results(promises)
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

fn sign_promise(target_contract: &AccountId, request: SignRequestArgs) -> Promise {
    ext_mpc_contract::ext(target_contract.clone())
        .with_attached_deposit(NearToken::from_yoctonear(1))
        .with_static_gas(Gas::from_tgas(SIGN_CALL_TGAS))
        .with_unused_gas_weight(0)
        .sign(request)
}

fn ckd_promise(target_contract: &AccountId, request: CKDRequestArgs) -> Promise {
    ext_mpc_contract::ext(target_contract.clone())
        .with_attached_deposit(NearToken::from_yoctonear(1))
        .with_static_gas(Gas::from_tgas(CKD_CALL_TGAS))
        .with_unused_gas_weight(0)
        .request_app_private_key(request)
}

/// Combines the given child promises via [`Promise::and`], chains `handle_results` as
/// the resolution callback, and returns the resulting promise. `handle_results`
/// observes every child's resolution and panics if any of them failed, so a parent
/// transaction that completes with `Ok` is proof that every queued call resolved.
fn join_with_handle_results(mut promises: Vec<Promise>) -> Promise {
    promises.reverse();
    let mut combined_promise = promises.pop().unwrap();
    while !promises.is_empty() {
        combined_promise = combined_promise.and(promises.pop().unwrap());
    }
    combined_promise.then(
        TestContract::ext_self()
            .with_static_gas(Gas::from_tgas(HANDLE_RESULTS_TGAS))
            .with_unused_gas_weight(0)
            .handle_results(),
    )
}
