//! Off-chain convenience: full local verification in one call.
//!
//! Combines `attestation::DstackVerify::verify` (the `dcap_qvl`
//! cryptographic call) with `Attestation::finish_verify` (the post-DCAP
//! checks). Mirrors the behavior of the deleted combined
//! `Attestation::verify` method.
//!
//! Off-chain consumers (`tee-authority`, `attestation-cli`, `mpc-node`,
//! integration tests) call this. The on-chain `mpc-contract` does NOT
//! use it — it delegates the cryptographic call to the verifier contract
//! via Promise + callback (see `mpc_contract::on_attestation_verified`).
//! That's how `dcap-qvl` and its closure stay out of the contract's WASM.

use alloc::string::ToString as _;

use attestation::attestation::DstackVerify as _;
use attestation_types::{
    measurements::ExpectedMeasurements, report_data::ReportData,
    verify_post_dcap::VerificationError,
};
use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};

use crate::attestation::{Attestation, VerifiedAttestation};

/// One-shot local verification: runs `dcap_qvl::verify::verify`
/// followed by the post-DCAP checks against the resulting mirror
/// `VerifiedReport`. Returns the `VerifiedAttestation` on success.
///
/// `Mock` attestations skip the dcap-qvl call (they have no quote);
/// the post-DCAP path handles them via the existing
/// `verify_mock_attestation` flow.
pub fn local_verify(
    attestation: &Attestation,
    expected_report_data: ReportData,
    timestamp_seconds: u64,
    allowed_mpc_docker_image_hashes: &[NodeImageHash],
    allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    accepted_measurements: &[ExpectedMeasurements],
) -> Result<VerifiedAttestation, VerificationError> {
    let verified_report = match attestation {
        Attestation::Dstack(dstack) => {
            let _matched = dstack.verify(
                expected_report_data.clone(),
                timestamp_seconds,
                accepted_measurements,
            )?;
            local_dcap_verify(dstack, timestamp_seconds)?
        }
        Attestation::Mock(_) => zero_verified_report(),
    };

    attestation.finish_verify(
        &verified_report,
        expected_report_data,
        allowed_mpc_docker_image_hashes,
        allowed_launcher_docker_compose_hashes,
        accepted_measurements,
        timestamp_seconds,
    )
}

/// Runs the `dcap_qvl::verify::verify` cryptographic call against a
/// `DstackAttestation` and returns the result as the wire-mirror
/// `VerifiedReport`. Useful for tests that need a real, well-formed
/// `VerifiedReport` (e.g. exercising the post-DCAP path on its own).
pub fn dstack_to_verified_report(
    dstack: &crate::attestation::DstackAttestation,
    timestamp_seconds: u64,
) -> Result<tee_verifier_interface::VerifiedReport, VerificationError> {
    local_dcap_verify(dstack, timestamp_seconds)
}

fn local_dcap_verify(
    dstack: &crate::attestation::DstackAttestation,
    timestamp_seconds: u64,
) -> Result<tee_verifier_interface::VerifiedReport, VerificationError> {
    let collateral = ::attestation::collateral_to_dcap(dstack.collateral.clone());
    let verification_result =
        dcap_qvl::verify::verify(&dstack.quote, &collateral, timestamp_seconds)
            .map_err(|e| VerificationError::DcapVerification(e.to_string()))?;
    Ok(dcap_to_mirror(verification_result))
}

fn dcap_to_mirror(
    value: dcap_qvl::verify::VerifiedReport,
) -> tee_verifier_interface::VerifiedReport {
    tee_verifier_interface::VerifiedReport {
        status: value.status,
        advisory_ids: value.advisory_ids,
        report: match value.report {
            dcap_qvl::quote::Report::SgxEnclave(_) => {
                panic!("SGX enclave reports are not supported by mpc-attestation")
            }
            dcap_qvl::quote::Report::TD10(r) => {
                tee_verifier_interface::Report::TD10(td10_to_mirror(r))
            }
            dcap_qvl::quote::Report::TD15(r) => {
                tee_verifier_interface::Report::TD15(tee_verifier_interface::TDReport15 {
                    base: td10_to_mirror(r.base),
                    tee_tcb_svn2: r.tee_tcb_svn2,
                    mr_service_td: r.mr_service_td,
                })
            }
        },
        ppid: value.ppid,
        qe_status: tcb_status_with_advisory_to_mirror(value.qe_status),
        platform_status: tcb_status_with_advisory_to_mirror(value.platform_status),
    }
}

fn td10_to_mirror(value: dcap_qvl::quote::TDReport10) -> tee_verifier_interface::TDReport10 {
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

fn tcb_status_with_advisory_to_mirror(
    value: dcap_qvl::tcb_info::TcbStatusWithAdvisory,
) -> tee_verifier_interface::TcbStatusWithAdvisory {
    tee_verifier_interface::TcbStatusWithAdvisory {
        status: match value.status {
            dcap_qvl::tcb_info::TcbStatus::UpToDate => tee_verifier_interface::TcbStatus::UpToDate,
            dcap_qvl::tcb_info::TcbStatus::OutOfDateConfigurationNeeded => {
                tee_verifier_interface::TcbStatus::OutOfDateConfigurationNeeded
            }
            dcap_qvl::tcb_info::TcbStatus::OutOfDate => {
                tee_verifier_interface::TcbStatus::OutOfDate
            }
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
        },
        advisory_ids: value.advisory_ids,
    }
}

fn zero_verified_report() -> tee_verifier_interface::VerifiedReport {
    tee_verifier_interface::VerifiedReport {
        status: alloc::string::String::new(),
        advisory_ids: alloc::vec::Vec::new(),
        report: tee_verifier_interface::Report::TD10(tee_verifier_interface::TDReport10 {
            tee_tcb_svn: [0; 16],
            mr_seam: [0; 48],
            mr_signer_seam: [0; 48],
            seam_attributes: [0; 8],
            td_attributes: [0; 8],
            xfam: [0; 8],
            mr_td: [0; 48],
            mr_config_id: [0; 48],
            mr_owner: [0; 48],
            mr_owner_config: [0; 48],
            rt_mr0: [0; 48],
            rt_mr1: [0; 48],
            rt_mr2: [0; 48],
            rt_mr3: [0; 48],
            report_data: [0; 64],
        }),
        ppid: alloc::vec::Vec::new(),
        qe_status: tee_verifier_interface::TcbStatusWithAdvisory {
            status: tee_verifier_interface::TcbStatus::UpToDate,
            advisory_ids: alloc::vec::Vec::new(),
        },
        platform_status: tee_verifier_interface::TcbStatusWithAdvisory {
            status: tee_verifier_interface::TcbStatus::UpToDate,
            advisory_ids: alloc::vec::Vec::new(),
        },
    }
}
