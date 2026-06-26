//! Builders for the contract calls made by the node, devnet, and the tests.
//!
//! Each `make_*` returns a [`FunctionCallArgs`] with the method-appropriate gas and deposit baked
//! in (only `make_propose_update`'s deposit varies, so it stays a parameter). `respond` /
//! `respond_ckd` / `respond_verify_foreign_tx` are absent: the node sends node-side request wrappers
//! (the contract's `SignatureRequest`/`CKDRequest` are receive-only and not `Serialize`), so the
//! node builds those.

use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use serde::Serialize;

use crate::method_names;
use crate::types::{
    BackupServiceInfo, CKDRequestArgs, DestinationNodeInfo, DomainConfig, EpochId, InitConfig,
    KeyEventId, Keyset, NodeImageHash, ProposedThresholdParameters, PublicKey, SignRequestArgs,
    SubmitParticipantInfoArgs, SupportedForeignChains, ThresholdParameters,
    VerifyForeignTransactionRequestArgs,
};

/// Gas for votes, admin, and init calls.
const MAX_GAS: NearGas = NearGas::from_tgas(300);
/// Gas for a `sign` (and `verify_foreign_transaction`) request.
const SIGN_GAS: NearGas = NearGas::from_tgas(15);
/// Gas for a `request_app_private_key` (CKD) request.
const CKD_GAS: NearGas = NearGas::from_tgas(100);
const NO_DEPOSIT: NearToken = NearToken::from_yoctonear(0);
/// The 1 yoctoNEAR attached to user requests for full-access-key confirmation.
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

fn json_call<T: Serialize>(
    method_name: &'static str,
    args: &T,
    gas: NearGas,
    deposit: NearToken,
) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: method_name.to_string(),
        args: serde_json::to_vec(args).expect("contract call args are serializable"),
        gas,
        deposit,
    }
}

fn no_args_call(method_name: &'static str) -> FunctionCallArgs {
    FunctionCallArgs {
        method_name: method_name.to_string(),
        args: b"{}".to_vec(),
        gas: MAX_GAS,
        deposit: NO_DEPOSIT,
    }
}

/// Generates a `make_*` builder whose JSON body is a private `Args` wrapper struct. The parameter
/// list and the serialized field names/order are taken verbatim from the `{ field: Type, .. }` list.
macro_rules! make_json {
    ($(#[$m:meta])* $fn:ident, $method:ident, { $($field:ident : $ty:ty),* $(,)? }, $gas:expr, $deposit:expr) => {
        $(#[$m])*
        pub fn $fn($($field: $ty),*) -> FunctionCallArgs {
            #[derive(Serialize)]
            struct Args { $($field: $ty),* }
            json_call(method_names::$method, &Args { $($field),* }, $gas, $deposit)
        }
    };
}

// --- Node methods ---

make_json!(make_vote_pk, VOTE_PK, { key_event_id: KeyEventId, public_key: PublicKey }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_reshared, VOTE_RESHARED, { key_event_id: KeyEventId }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_abort_key_event_instance, VOTE_ABORT_KEY_EVENT_INSTANCE, { key_event_id: KeyEventId }, MAX_GAS, NO_DEPOSIT);
make_json!(make_start_keygen_instance, START_KEYGEN_INSTANCE, { key_event_id: KeyEventId }, MAX_GAS, NO_DEPOSIT);
make_json!(make_start_reshare_instance, START_RESHARE_INSTANCE, { key_event_id: KeyEventId }, MAX_GAS, NO_DEPOSIT);

pub fn make_conclude_node_migration(keyset: &Keyset) -> FunctionCallArgs {
    #[derive(Serialize)]
    struct Args<'a> {
        keyset: &'a Keyset,
    }
    json_call(
        method_names::CONCLUDE_NODE_MIGRATION,
        &Args { keyset },
        MAX_GAS,
        NO_DEPOSIT,
    )
}

pub fn make_submit_participant_info(args: &SubmitParticipantInfoArgs) -> FunctionCallArgs {
    json_call(method_names::SUBMIT_PARTICIPANT_INFO, args, MAX_GAS, NO_DEPOSIT)
}

pub fn make_verify_tee() -> FunctionCallArgs {
    no_args_call(method_names::VERIFY_TEE)
}

// --- Vote/admin/init methods ---

make_json!(make_vote_add_domains, VOTE_ADD_DOMAINS, { domains: Vec<DomainConfig> }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_new_parameters, VOTE_NEW_PARAMETERS, { prospective_epoch_id: EpochId, proposal: ProposedThresholdParameters }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_code_hash, VOTE_CODE_HASH, { code_hash: NodeImageHash }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_update, VOTE_UPDATE, { id: u64 }, MAX_GAS, NO_DEPOSIT);
make_json!(make_vote_cancel_keygen, VOTE_CANCEL_KEYGEN, { next_domain_id: u64 }, MAX_GAS, NO_DEPOSIT);

pub fn make_vote_cancel_resharing() -> FunctionCallArgs {
    no_args_call(method_names::VOTE_CANCEL_RESHARING)
}

make_json!(make_init, INIT, { parameters: ThresholdParameters, init_config: Option<InitConfig> }, MAX_GAS, NO_DEPOSIT);
make_json!(make_register_backup_service, REGISTER_BACKUP_SERVICE, { backup_service_info: BackupServiceInfo }, MAX_GAS, NO_DEPOSIT);
make_json!(make_register_foreign_chain_support, REGISTER_FOREIGN_CHAIN_SUPPORT, { foreign_chain_support: SupportedForeignChains }, MAX_GAS, NO_DEPOSIT);
make_json!(make_start_node_migration, START_NODE_MIGRATION, { destination_node_info: DestinationNodeInfo }, MAX_GAS, NO_DEPOSIT);

// --- User requests (1 yoctoNEAR deposit) ---

make_json!(make_sign, SIGN, { request: SignRequestArgs }, SIGN_GAS, ONE_YOCTO);
make_json!(make_request_app_private_key, REQUEST_APP_PRIVATE_KEY, { request: CKDRequestArgs }, CKD_GAS, ONE_YOCTO);
make_json!(make_verify_foreign_transaction, VERIFY_FOREIGN_TRANSACTION, { request: VerifyForeignTransactionRequestArgs }, SIGN_GAS, ONE_YOCTO);

/// `propose_update` takes Borsh-encoded args (a single `#[serializer(borsh)]` parameter). `config`
/// updates are not supported here — only a code (wasm) upgrade, matching how devnet/the tests use
/// it. The deposit (storage staking for the proposed code) is caller-supplied.
pub fn make_propose_update(code: Option<Vec<u8>>, deposit: NearToken) -> FunctionCallArgs {
    #[derive(borsh::BorshSerialize)]
    struct Args {
        code: Option<Vec<u8>>,
        config: Option<()>,
    }
    FunctionCallArgs {
        method_name: method_names::PROPOSE_UPDATE.to_string(),
        args: borsh::to_vec(&Args { code, config: None }).expect("borsh serialization is infallible"),
        gas: MAX_GAS,
        deposit,
    }
}
