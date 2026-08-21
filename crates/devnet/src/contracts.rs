use blstrs::G1Projective;
use group::Group;
use near_account_id::AccountId;
use near_mpc_bounded_collections::UpperBoundedVec;
use near_mpc_contract_interface::{
    method_names,
    types::{
        Bls12381G1PublicKey, CKDAppPublicKey, CKDRequestArgs, DomainConfig,
        EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES, Payload, Protocol,
    },
};
use near_primitives::action::Action;
use near_primitives::types::{Balance, Gas};
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;

/// Gas attached to a `sign` (or legacy `sign`) request. Matches the e2e
/// test cluster's `SIGN_GAS` and the contract's
/// `sign_call_gas_attachment_requirement_tera_gas` minimum.
const SIGN_TGAS: u64 = 15;
/// Gas attached to a `request_app_private_key` (CKD) call. Matches the
/// e2e cluster's `CKD_PV_GAS`. CKD is more expensive than `sign` because
/// [`AppPublicKeyPV`](CKDAppPublicKey::AppPublicKeyPV) does an on-chain bls12381 pairing check before
/// yielding.
const CKD_TGAS: u64 = 100;

#[derive(Clone)]
pub struct ActionCall {
    pub receiver_id: AccountId,
    pub actions: Vec<Action>,
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
    LegacySign(LegacySignActionCallArgs),
    Ckd(RequestActionCallArgs),
}

pub fn make_actions(call: ContractActionCall) -> ActionCall {
    match call {
        ContractActionCall::LegacySign(args) => ActionCall {
            receiver_id: args.mpc_contract,
            actions: vec![make_action(
                method_names::SIGN,
                &serde_json::to_vec(&SignArgsV1 {
                    request: SignRequestV1 {
                        key_version: 0,
                        path: "".to_string(),
                        payload: rand::random(),
                    },
                })
                .unwrap(),
                SIGN_TGAS,
                1,
            )],
        },
        ContractActionCall::Ckd(args) => ActionCall {
            receiver_id: args.mpc_contract,
            actions: vec![make_action(
                method_names::REQUEST_APP_PRIVATE_KEY,
                &serde_json::to_vec(&CKDArgs {
                    request: CKDRequestArgs {
                        derivation_path: "".to_string(),
                        domain_id: args.domain_config.id,
                        app_public_key: CKDAppPublicKey::AppPublicKey(random_app_public_key()),
                    },
                })
                .unwrap(),
                CKD_TGAS,
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
struct CKDArgs {
    pub request: CKDRequestArgs,
}

pub(crate) fn make_payload(protocol: Protocol) -> Payload {
    match protocol {
        Protocol::CaitSith | Protocol::DamgardEtAl => {
            Payload::Ecdsa(rand::random::<[u8; 32]>().into())
        }
        Protocol::Frost => {
            let mut rng = rand::thread_rng();
            let len = rng.gen_range(0..=EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES);
            let mut payload = vec![0; len];
            rng.fill_bytes(&mut payload);

            let bounded_payload: UpperBoundedVec<u8, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES> =
                payload.try_into().unwrap();

            Payload::Eddsa(bounded_payload)
        }
        Protocol::ConfidentialKeyDerivation => {
            unreachable!(
                "make_payload should not be called with `ConfidentialKeyDerivation` protocol"
            )
        }
    }
}

fn random_app_public_key() -> Bls12381G1PublicKey {
    let point = G1Projective::random(&mut OsRng);
    (&point).into()
}

fn make_action(method: &str, args: &[u8], tgas: u64, deposit: u128) -> Action {
    Action::FunctionCall(Box::new(near_primitives::action::FunctionCallAction {
        method_name: method.to_string(),
        args: args.to_vec(),
        gas: Gas::from_teragas(tgas),
        deposit: Balance::from_yoctonear(deposit),
    }))
}
