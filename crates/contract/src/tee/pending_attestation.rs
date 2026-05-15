//! `PendingAttestation` — state stashed between `submit_participant_info`
//! and the `on_attestation_verified` callback that resolves after the
//! `tee-verifier.near` Promise returns.
//!
//! `submit_participant_info` ([`crate::lib::submit_participant_info`])
//! cannot do the cryptographic quote verification on-chain — that work
//! lives in the `tee-verifier` contract, reached over a cross-contract
//! Promise. The Promise call returns asynchronously; the contract has
//! to remember which `account_id`'s submission is pending so the
//! callback can resume.
//!
//! Stored entries are short-lived: created on Promise dispatch, removed
//! when `on_attestation_verified` fires (whether successfully or with a
//! `PromiseError`). Each entry holds the inputs the callback needs to
//! complete verification and apply the storage-deposit refund.

use attestation_types::{dstack_attestation::DstackAttestation, report_data::ReportData};
use near_sdk::{near, NearToken, StorageUsage};

use crate::tee::tee_state::NodeId;

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct PendingAttestation {
    /// The `NodeId` derived from the caller (account_id, tls_pk,
    /// account_pk). The callback uses this to insert into
    /// `stored_attestations`.
    pub node_id: NodeId,

    /// Hash of `(tls_pk, account_pk)` bound into the quote's
    /// `report_data`. The callback re-checks the mirror's report_data
    /// against this value during post-DCAP verification.
    pub report_data: ReportData,

    /// The `Dstack` attestation payload submitted. Carries the
    /// `tcb_info` the callback needs for RTMR3 replay + app_compose
    /// validation. Only `Dstack` attestations reach this struct;
    /// `Mock` attestations stay on the synchronous path and never
    /// produce a pending entry.
    pub attestation: DstackAttestation,

    /// Amount the caller attached to `submit_participant_info`. The
    /// callback either consumes it against the storage-staking cost of
    /// the inserted `stored_attestations` entry or refunds it in full
    /// on verification failure.
    pub attached_deposit: NearToken,

    /// Contract storage usage measured *before* the pending entry was
    /// inserted. The callback uses this baseline to compute the storage
    /// delta a successful insertion produced and charge accordingly.
    pub initial_storage_usage: StorageUsage,
}
