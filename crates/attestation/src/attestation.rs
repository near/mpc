//! Local off-chain TEE attestation verification.
//!
//! Carries the `DstackAttestation` struct and its [`DstackAttestation::verify`]
//! method, which is the *only* place the heavy `dcap_qvl::verify::verify`
//! cryptographic call is made. After that call, the parsed report is
//! converted to the [`tee_verifier_interface::VerifiedReport`] mirror and
//! the post-DCAP checks are run via the free functions in
//! [`attestation_types::verify_post_dcap`] — same code path the
//! `tee-verifier` contract uses on its callback side.
//!
//! Consumers that don't need to run `dcap-qvl` locally should depend on
//! `attestation-types` directly, not this crate.

use alloc::{
    format,
    string::{String, ToString},
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};

use attestation_types::{
    measurements::ExpectedMeasurements,
    report_data::ReportData,
    tcb_info::TcbInfo,
    verify_post_dcap::{
        verify_any_measurements, verify_app_compose, verify_report_data, verify_rtmr3,
        verify_tcb_status,
    },
};

// Re-export the post-DCAP helper traits and the error type at the historical
// `attestation::attestation::*` paths so existing consumers (e.g.
// `mpc-attestation`) keep working without import-path churn.
pub use attestation_types::verify_post_dcap::{GetSingleEvent, OrErr, VerificationError};

use crate::{collateral::Collateral, quote::QuoteBytes};

#[derive(Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct DstackAttestation {
    pub quote: QuoteBytes,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
}

impl fmt::Debug for DstackAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_BYTES: usize = 2048;

        fn truncate_debug<T: fmt::Debug>(value: &T, max_bytes: usize) -> String {
            let debug_str = format!("{:?}", value);
            if debug_str.len() <= max_bytes {
                debug_str
            } else {
                format!(
                    "{}... (truncated {} bytes)",
                    &debug_str[..max_bytes],
                    debug_str.len() - max_bytes
                )
            }
        }

        f.debug_struct("DstackAttestation")
            .field("quote", &truncate_debug(&self.quote, MAX_BYTES))
            .field("collateral", &truncate_debug(&self.collateral, MAX_BYTES))
            .field("tcb_info", &truncate_debug(&self.tcb_info, MAX_BYTES))
            .finish()
    }
}

impl DstackAttestation {
    /// Checks whether this attestation is valid with respect to expected values of:
    /// - `expected_report_data`: must be measured correctly in RTMR3
    /// - `timestamp_seconds`: current UNIX time in seconds
    /// - `accepted_measurements`: set of accepted RTMRs and key-provider event digest.
    ///   If any element in the set is valid, the function accepts the attestation as valid.
    ///
    /// On success, returns the matched measurements.
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        timestamp_seconds: u64,
        accepted_measurements: &[ExpectedMeasurements],
    ) -> Result<ExpectedMeasurements, VerificationError> {
        let verification_result =
            dcap_qvl::verify::verify(&self.quote, &self.collateral, timestamp_seconds)
                .map_err(|e| VerificationError::DcapVerification(e.to_string()))?;

        let verified_report = to_mirror_verified_report(verification_result);

        let report_data = verified_report
            .report
            .as_td10()
            .ok_or(VerificationError::ReportNotTd10)?;

        verify_tcb_status(&verified_report)?;
        verify_report_data(&expected_report_data, report_data)?;
        verify_rtmr3(report_data, &self.tcb_info)?;
        verify_app_compose(&self.tcb_info)?;

        verify_any_measurements(report_data, &self.tcb_info, accepted_measurements)
    }
}

/// Converts `dcap_qvl::verify::VerifiedReport` (serde-only upstream type) into
/// the Borsh-stable [`tee_verifier_interface::VerifiedReport`] mirror that
/// the post-DCAP helpers operate on.
///
/// Duplicated in `crates/tee-verifier/src/conversions.rs` for the on-chain
/// verifier; kept here as well to avoid pulling the full `attestation`
/// crate into the verifier-contract dep graph.
fn to_mirror_verified_report(
    value: dcap_qvl::verify::VerifiedReport,
) -> tee_verifier_interface::VerifiedReport {
    tee_verifier_interface::VerifiedReport {
        status: value.status,
        advisory_ids: value.advisory_ids,
        report: to_mirror_report(value.report),
        ppid: value.ppid,
        qe_status: to_mirror_tcb_status_with_advisory(value.qe_status),
        platform_status: to_mirror_tcb_status_with_advisory(value.platform_status),
    }
}

fn to_mirror_report(value: dcap_qvl::quote::Report) -> tee_verifier_interface::Report {
    match value {
        dcap_qvl::quote::Report::SgxEnclave(r) => {
            tee_verifier_interface::Report::SgxEnclave(to_mirror_enclave_report(r))
        }
        dcap_qvl::quote::Report::TD10(r) => tee_verifier_interface::Report::TD10(to_mirror_td10(r)),
        dcap_qvl::quote::Report::TD15(r) => tee_verifier_interface::Report::TD15(to_mirror_td15(r)),
    }
}

fn to_mirror_td10(value: dcap_qvl::quote::TDReport10) -> tee_verifier_interface::TDReport10 {
    tee_verifier_interface::TDReport10 {
        tee_tcb_svn: value.tee_tcb_svn,
        mr_seam: value.mr_seam,
        mr_signer_seam: value.mr_signer_seam,
        seam_attributes: value.seam_attributes,
        td_attributes: value.td_attributes,
        xfam: value.xfam,
        mr_td: value.mr_td,
        mr_config_id: value.mr_config_id,
        mr_owner: value.mr_owner,
        mr_owner_config: value.mr_owner_config,
        rt_mr0: value.rt_mr0,
        rt_mr1: value.rt_mr1,
        rt_mr2: value.rt_mr2,
        rt_mr3: value.rt_mr3,
        report_data: value.report_data,
    }
}

fn to_mirror_td15(value: dcap_qvl::quote::TDReport15) -> tee_verifier_interface::TDReport15 {
    tee_verifier_interface::TDReport15 {
        base: to_mirror_td10(value.base),
        tee_tcb_svn2: value.tee_tcb_svn2,
        mr_service_td: value.mr_service_td,
    }
}

fn to_mirror_enclave_report(
    value: dcap_qvl::quote::EnclaveReport,
) -> tee_verifier_interface::EnclaveReport {
    tee_verifier_interface::EnclaveReport {
        cpu_svn: value.cpu_svn,
        misc_select: value.misc_select,
        reserved1: value.reserved1,
        attributes: value.attributes,
        mr_enclave: value.mr_enclave,
        reserved2: value.reserved2,
        mr_signer: value.mr_signer,
        reserved3: value.reserved3,
        isv_prod_id: value.isv_prod_id,
        isv_svn: value.isv_svn,
        reserved4: value.reserved4,
        report_data: value.report_data,
    }
}

fn to_mirror_tcb_status(value: dcap_qvl::tcb_info::TcbStatus) -> tee_verifier_interface::TcbStatus {
    match value {
        dcap_qvl::tcb_info::TcbStatus::UpToDate => tee_verifier_interface::TcbStatus::UpToDate,
        dcap_qvl::tcb_info::TcbStatus::OutOfDateConfigurationNeeded => {
            tee_verifier_interface::TcbStatus::OutOfDateConfigurationNeeded
        }
        dcap_qvl::tcb_info::TcbStatus::OutOfDate => tee_verifier_interface::TcbStatus::OutOfDate,
        dcap_qvl::tcb_info::TcbStatus::ConfigurationAndSWHardeningNeeded => {
            tee_verifier_interface::TcbStatus::ConfigurationAndSWHardeningNeeded
        }
        dcap_qvl::tcb_info::TcbStatus::ConfigurationNeeded => {
            tee_verifier_interface::TcbStatus::ConfigurationNeeded
        }
        dcap_qvl::tcb_info::TcbStatus::SWHardeningNeeded => {
            tee_verifier_interface::TcbStatus::SWHardeningNeeded
        }
        dcap_qvl::tcb_info::TcbStatus::Revoked => tee_verifier_interface::TcbStatus::Revoked,
    }
}

fn to_mirror_tcb_status_with_advisory(
    value: dcap_qvl::tcb_info::TcbStatusWithAdvisory,
) -> tee_verifier_interface::TcbStatusWithAdvisory {
    tee_verifier_interface::TcbStatusWithAdvisory {
        status: to_mirror_tcb_status(value.status),
        advisory_ids: value.advisory_ids,
    }
}
