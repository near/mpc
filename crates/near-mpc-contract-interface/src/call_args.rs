//! Builders for the contract calls the MPC node makes, each returning a [`FunctionCallArgs`].
//!
//! The `respond` family is absent: the node sends node-side request wrappers (the contract's
//! `SignatureRequest`/`CKDRequest` are receive-only and not `Serialize`), so the node builds those.

use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use serde::Serialize;

use crate::method_names;
use crate::types::{KeyEventId, Keyset, PublicKey, SubmitParticipantInfoArgs};

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
