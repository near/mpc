use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use futures::future::join_all;
use mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS;
use mpc_devnet::read_contract_state;
use mpc_devnet::rpc::NearRpcClients;
use mpc_primitives::hash::NodeImageHash;
use near_jsonrpc_client::methods::query::RpcQueryRequest;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_mpc_contract_interface::method_names::GET_ATTESTATION;
use near_mpc_contract_interface::types::{
    AccountId, Ed25519PublicKey, EpochId, MockAttestation, ParticipantId, ProtocolContractState,
    ThresholdParameters, VerifiedAttestation,
};
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::QueryRequest;
use serde::Serialize;

use crate::docker_hub;

/// Mirrors `mpc_node::run::ATTESTATION_RESUBMISSION_INTERVAL`
/// (`crates/node/src/run.rs:51`). Re-declared rather than imported to avoid
/// pulling the entire `mpc-node` dependency tree (rocksdb, indexer, ...).
pub const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// One row per participant occurrence in some epoch's participant set.
///
/// In `Running` every participant yields one row. In `Resharing` a participant
/// in both the old and the new set yields two rows (one per epoch); a
/// participant in only one set yields a single row.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipantRow {
    pub epoch_id: EpochId,
    pub account_id: AccountId,
    pub participant_id: ParticipantId,
    pub tls_public_key: Ed25519PublicKey,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct NetworkSnapshot {
    pub fetched_at_unix_seconds: u64,
    pub state: ProtocolContractState,
    pub attestations: BTreeMap<Ed25519PublicKey, AttestationResult>,
    pub mpc_image_versions: BTreeMap<NodeImageHash, String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[expect(clippy::large_enum_variant)]
pub enum AttestationResult {
    Ok(Option<VerifiedAttestation>),
    Err(String),
}

pub async fn collect(rpc: &Arc<NearRpcClients>, contract: &AccountId) -> anyhow::Result<NetworkSnapshot> {
    let state = read_contract_state(rpc, contract).await;

    let rows = participants_with_epochs(&state);
    if rows.is_empty() {
        anyhow::bail!(
            "contract is in `{}` state; no participant TLS keys to query",
            describe_state_variant(&state)
        );
    }

    let unique_keys: BTreeSet<Ed25519PublicKey> =
        rows.iter().map(|r| r.tls_public_key.clone()).collect();

    let attestation_fetch = fetch_all_attestations(rpc, contract, unique_keys);
    let version_fetch = docker_hub::fetch_mpc_image_versions();
    let (attestations, mpc_image_versions) = tokio::join!(attestation_fetch, version_fetch);

    Ok(NetworkSnapshot {
        fetched_at_unix_seconds: now_unix_seconds(),
        state,
        attestations,
        mpc_image_versions,
    })
}

async fn fetch_all_attestations(
    rpc: &Arc<NearRpcClients>,
    contract: &AccountId,
    keys: BTreeSet<Ed25519PublicKey>,
) -> BTreeMap<Ed25519PublicKey, AttestationResult> {
    let fetches = keys.into_iter().map(|tls_public_key| async move {
        let result = fetch_attestation(rpc, contract, &tls_public_key).await;
        let result = match result {
            Ok(opt) => AttestationResult::Ok(opt),
            Err(e) => AttestationResult::Err(format!("{e:#}")),
        };
        (tls_public_key, result)
    });
    join_all(fetches).await.into_iter().collect()
}

async fn fetch_attestation(
    rpc: &Arc<NearRpcClients>,
    contract: &AccountId,
    tls_public_key: &Ed25519PublicKey,
) -> anyhow::Result<Option<VerifiedAttestation>> {
    let args = serde_json::to_vec(&serde_json::json!({
        "tls_public_key": tls_public_key,
    }))?;
    let request = RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: contract.clone(),
            method_name: GET_ATTESTATION.to_string(),
            args: FunctionArgs::from(args),
        },
    };
    let response = rpc
        .submit(request)
        .await
        .context("RPC query for get_attestation failed")?;
    match response.kind {
        QueryResponseKind::CallResult(r) => {
            serde_json::from_slice(&r.result).context("deserializing get_attestation response")
        }
        other => anyhow::bail!("unexpected response kind: {other:?}"),
    }
}

/// Enumerate participants tagged with the epoch they belong to.
pub fn participants_with_epochs(state: &ProtocolContractState) -> Vec<ParticipantRow> {
    let mut out = Vec::new();
    match state {
        ProtocolContractState::NotInitialized | ProtocolContractState::Initializing(_) => {}
        ProtocolContractState::Running(running) => {
            push_participants(&mut out, running.keyset.epoch_id, &running.parameters);
        }
        ProtocolContractState::Resharing(resharing) => {
            push_participants(
                &mut out,
                resharing.previous_running_state.keyset.epoch_id,
                &resharing.previous_running_state.parameters,
            );
            push_participants(
                &mut out,
                resharing.resharing_key.epoch_id,
                &resharing.resharing_key.parameters,
            );
        }
    }
    out
}

fn push_participants(
    out: &mut Vec<ParticipantRow>,
    epoch_id: EpochId,
    params: &ThresholdParameters,
) {
    for (account_id, participant_id, info) in &params.participants.participants {
        out.push(ParticipantRow {
            epoch_id,
            account_id: account_id.clone(),
            participant_id: *participant_id,
            tls_public_key: info.tls_public_key.clone(),
            url: info.url.clone(),
        });
    }
}

fn describe_state_variant(state: &ProtocolContractState) -> &'static str {
    match state {
        ProtocolContractState::NotInitialized => "NotInitialized",
        ProtocolContractState::Initializing(_) => "Initializing",
        ProtocolContractState::Running(_) => "Running",
        ProtocolContractState::Resharing(_) => "Resharing",
    }
}

/// Unix seconds at which the attestation expires, or `None` for mock
/// variants that carry no expiry.
pub fn expiry_unix_seconds(att: &VerifiedAttestation) -> Option<u64> {
    match att {
        VerifiedAttestation::Dstack(d) => Some(d.expiry_timestamp_seconds),
        VerifiedAttestation::Mock(MockAttestation::WithConstraints {
            expiry_timestamp_seconds,
            ..
        }) => *expiry_timestamp_seconds,
        VerifiedAttestation::Mock(_) => None,
    }
}

/// Unix seconds at which the attestation was submitted, derived as
/// `expiry - DEFAULT_EXPIRATION_DURATION_SECONDS`.
pub fn submitted_at(att: &VerifiedAttestation) -> Option<u64> {
    expiry_unix_seconds(att).map(|e| e.saturating_sub(DEFAULT_EXPIRATION_DURATION_SECONDS))
}

/// True if the attestation expires before the next scheduled re-submission
/// — i.e. the node has missed at least one submission window.
pub fn is_stale(att: &VerifiedAttestation, now_unix_seconds: u64) -> bool {
    let Some(expiry) = expiry_unix_seconds(att) else {
        return false;
    };
    let resubmission = ATTESTATION_RESUBMISSION_INTERVAL.as_secs();
    expiry < now_unix_seconds.saturating_add(resubmission)
}

pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Short status word used by the table renderer and the trailing summary.
pub fn attestation_status(result: Option<&AttestationResult>, now: u64) -> &'static str {
    match result {
        None => "no-key",
        Some(AttestationResult::Err(_)) => "rpc-error",
        Some(AttestationResult::Ok(None)) => "missing",
        Some(AttestationResult::Ok(Some(att))) => {
            if is_stale(att, now) {
                "stale"
            } else {
                "healthy"
            }
        }
    }
}

/// Rows sorted by `tls_public_key`, the order the table renderer wants.
pub fn rows_sorted_by_tls(state: &ProtocolContractState) -> Vec<ParticipantRow> {
    let mut rows = participants_with_epochs(state);
    rows.sort_by(|a, b| {
        a.tls_public_key
            .cmp(&b.tls_public_key)
            .then_with(|| a.epoch_id.cmp(&b.epoch_id))
    });
    rows
}
