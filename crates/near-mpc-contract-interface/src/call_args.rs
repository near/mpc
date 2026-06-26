//! Builders for the contract calls the MPC node makes.
//!
//! Each `make_*` returns a [`FunctionCallArgs`] (method name + JSON-encoded args + gas + deposit).
//! The JSON keys match the contract's parameter names so the encoded args are what the contract
//! deserializes.

use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use serde::Serialize;

use crate::method_names;
use crate::types::{
    CKDRequest, CKDResponse, KeyEventId, Keyset, PublicKey, SignatureRequest, SignatureResponse,
    SubmitParticipantInfoArgs, VerifyForeignTransactionRequest, VerifyForeignTransactionResponse,
};

/// Node-originated contract calls all use the 300 Tgas maximum and attach no deposit.
const GAS: NearGas = NearGas::from_tgas(300);
const NO_DEPOSIT: NearToken = NearToken::from_yoctonear(0);

fn encode<T: Serialize>(method_name: &'static str, args: &T) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: method_name.to_string(),
        args: serde_json::to_vec(args).expect("contract call args are always serializable"),
        gas: GAS,
        deposit: NO_DEPOSIT,
    }
}

#[derive(Serialize)]
struct KeyEventIdArgs {
    key_event_id: KeyEventId,
}

pub fn make_vote_pk(key_event_id: KeyEventId, public_key: PublicKey) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args {
        key_event_id: KeyEventId,
        public_key: PublicKey,
    }
    encode(
        method_names::VOTE_PK,
        &Args {
            key_event_id,
            public_key,
        },
    )
}

pub fn make_vote_reshared(key_event_id: KeyEventId) -> FunctionCallArgs {
    encode(method_names::VOTE_RESHARED, &KeyEventIdArgs { key_event_id })
}

pub fn make_vote_abort_key_event_instance(key_event_id: KeyEventId) -> FunctionCallArgs {
    encode(
        method_names::VOTE_ABORT_KEY_EVENT_INSTANCE,
        &KeyEventIdArgs { key_event_id },
    )
}

pub fn make_start_keygen_instance(key_event_id: KeyEventId) -> FunctionCallArgs {
    encode(
        method_names::START_KEYGEN_INSTANCE,
        &KeyEventIdArgs { key_event_id },
    )
}

pub fn make_start_reshare_instance(key_event_id: KeyEventId) -> FunctionCallArgs {
    encode(
        method_names::START_RESHARE_INSTANCE,
        &KeyEventIdArgs { key_event_id },
    )
}

pub fn make_conclude_node_migration(keyset: &Keyset) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args<'a> {
        keyset: &'a Keyset,
    }
    encode(method_names::CONCLUDE_NODE_MIGRATION, &Args { keyset })
}

pub fn make_submit_participant_info(args: &SubmitParticipantInfoArgs) -> FunctionCallArgs {
    encode(method_names::SUBMIT_PARTICIPANT_INFO, args)
}

pub fn make_verify_tee() -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: method_names::VERIFY_TEE.to_string(),
        args: b"{}".to_vec(),
        gas: GAS,
        deposit: NO_DEPOSIT,
    }
}

pub fn make_respond(request: SignatureRequest, response: SignatureResponse) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args {
        request: SignatureRequest,
        response: SignatureResponse,
    }
    encode(method_names::RESPOND, &Args { request, response })
}

pub fn make_respond_ckd(request: CKDRequest, response: CKDResponse) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args {
        request: CKDRequest,
        response: CKDResponse,
    }
    encode(method_names::RESPOND_CKD, &Args { request, response })
}

pub fn make_respond_verify_foreign_tx(
    request: VerifyForeignTransactionRequest,
    response: VerifyForeignTransactionResponse,
) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args {
        request: VerifyForeignTransactionRequest,
        response: VerifyForeignTransactionResponse,
    }
    encode(
        method_names::RESPOND_VERIFY_FOREIGN_TX,
        &Args { request, response },
    )
}
