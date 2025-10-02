use std::collections::BTreeMap;

use mpc_contract::primitives::{
    ckd::CKDRequestArgs,
    domain::{DomainConfig, SignatureScheme},
    signature::{Bytes, Payload, SignRequestArgs},
};
use near_primitives::action::Action;
use near_sdk::AccountId;
use rand::RngCore;
use serde::Serialize;

#[derive(Clone)]
pub struct ActionCall {
    pub receiver_id: AccountId,
    pub actions: Vec<Action>,
}

#[derive(Clone)]
pub struct ParallelSignCallArgs {
    pub parallel_sign_contract: AccountId,
    pub mpc_contract: AccountId,
    pub calls_by_domain: Vec<(DomainConfig, u64)>,
}

#[derive(Clone)]
pub struct RequestActionCallArgs {
    pub mpc_contract: AccountId,
    pub domain_config: DomainConfig,
}

#[derive(Clone)]
pub struct LegacySignActionCallArgs {
    pub mpc_contract: AccountId,
}

#[derive(Clone)]
pub enum ContractActionCall {
    ParallelSignCall(ParallelSignCallArgs),
    Sign(RequestActionCallArgs),
    LegacySign(LegacySignActionCallArgs),
    Ckd(RequestActionCallArgs),
}

pub fn make_actions(call: ContractActionCall) -> ActionCall {
    match call {
        ContractActionCall::ParallelSignCall(args) => {
            let mut ecdsa_calls_by_domain = BTreeMap::new();
            let mut eddsa_calls_by_domain = BTreeMap::new();
            let mut ckd_calls_by_domain = BTreeMap::new();
            for (domain, prot_calls) in args.calls_by_domain {
                match domain.scheme {
                    SignatureScheme::Secp256k1 => {
                        ecdsa_calls_by_domain.insert(domain.id.0, prot_calls);
                    }
                    SignatureScheme::Ed25519 => {
                        eddsa_calls_by_domain.insert(domain.id.0, prot_calls);
                    }
                    SignatureScheme::Bls12381 => {
                        ckd_calls_by_domain.insert(domain.id.0, prot_calls);
                    }
                }
            }
            ActionCall {
                receiver_id: args.parallel_sign_contract,
                actions: vec![make_action(
                    "make_parallel_sign_calls",
                    &serde_json::to_vec(&ParallelSignArgsV2 {
                        target_contract: args.mpc_contract,
                        ecdsa_calls_by_domain,
                        eddsa_calls_by_domain,
                        ckd_calls_by_domain,
                        seed: rand::random(),
                    })
                    .unwrap(),
                    300,
                    1,
                )],
            }
        }
        ContractActionCall::Sign(args) => ActionCall {
            receiver_id: args.mpc_contract,
            actions: vec![make_action(
                "sign",
                &serde_json::to_vec(&SignArgsV2 {
                    request: SignRequestArgs {
                        domain_id: Some(args.domain_config.id),
                        path: "".to_string(),
                        payload_v2: Some(make_payload(args.domain_config.scheme)),
                        ..Default::default()
                    },
                })
                .unwrap(),
                300,
                1,
            )],
        },
        ContractActionCall::LegacySign(args) => ActionCall {
            receiver_id: args.mpc_contract,
            actions: vec![make_action(
                "sign",
                &serde_json::to_vec(&SignArgsV1 {
                    request: SignRequestV1 {
                        key_version: 0,
                        path: "".to_string(),
                        payload: rand::random(),
                    },
                })
                .unwrap(),
                300,
                1,
            )],
        },
        ContractActionCall::Ckd(args) => ActionCall {
            receiver_id: args.mpc_contract,
            actions: vec![make_action(
                "request_app_private_key",
                &serde_json::to_vec(&CKDArgs {
                    request: CKDRequestArgs {
                        domain_id: args.domain_config.id,
                        app_public_key: mpc_contract::utils::random_app_public_key(),
                    },
                })
                .unwrap(),
                300,
                1,
            )],
        },
    }
}

#[derive(Serialize)]
struct SignArgsV1 {
    pub request: SignRequestV1,
}

#[derive(Serialize)]
struct SignRequestV1 {
    payload: [u8; 32],
    path: String,
    key_version: u32,
}

#[derive(Serialize)]
struct SignArgsV2 {
    pub request: SignRequestArgs,
}

#[derive(Serialize)]
struct CKDArgs {
    pub request: CKDRequestArgs,
}

#[derive(Serialize)]
struct ParallelSignArgsV2 {
    target_contract: AccountId,
    ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    eddsa_calls_by_domain: BTreeMap<u64, u64>,
    ckd_calls_by_domain: BTreeMap<u64, u64>,
    seed: u64,
}

fn make_payload(scheme: SignatureScheme) -> Payload {
    match scheme {
        SignatureScheme::Secp256k1 => {
            Payload::Ecdsa(Bytes::new(rand::random::<[u8; 32]>().to_vec()).unwrap())
        }
        SignatureScheme::Ed25519 => {
            let len = rand::random_range(32..=1232);
            let mut payload = vec![0; len];
            rand::rng().fill_bytes(&mut payload);
            Payload::Eddsa(Bytes::new(payload).unwrap())
        }
        SignatureScheme::Bls12381 => {
            unreachable!("make_payload should not be called with `Bls12381` scheme")
        }
    }
}

fn make_action(method: &str, args: &[u8], tgas: u64, deposit: u128) -> Action {
    Action::FunctionCall(Box::new(near_primitives::action::FunctionCallAction {
        method_name: method.to_string(),
        args: args.to_vec(),
        gas: tgas * 1_000_000_000_000,
        deposit,
    }))
}
