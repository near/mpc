//! Conversions between `dcap_qvl`'s types and the Borsh-mirrored types in
//! `tee-verifier-interface`.
//!
//! These conversions live here (in the contract crate that already
//! depends on `dcap-qvl`) rather than in `tee-verifier-interface`, so
//! that the interface crate stays free of `dcap-qvl` and can be linked
//! into consumer contracts without dragging in `ring`/`webpki`/X.509
//! parsing.
//!
//! Free functions are used rather than `From`/`Into` impls because the
//! orphan rule forbids implementing a foreign trait between two foreign
//! types from a third crate.

use dcap_qvl::{quote as dq_quote, tcb_info as dq_tcb, verify as dq_verify};
use tee_verifier_interface::{
    Collateral, EnclaveReport, QuoteBytes, Report, TDReport10, TDReport15, TcbStatus,
    TcbStatusWithAdvisory, VerifiedReport,
};

pub fn collateral_to_dcap(value: Collateral) -> dcap_qvl::QuoteCollateralV3 {
    dcap_qvl::QuoteCollateralV3 {
        pck_crl_issuer_chain: value.pck_crl_issuer_chain,
        root_ca_crl: value.root_ca_crl,
        pck_crl: value.pck_crl,
        tcb_info_issuer_chain: value.tcb_info_issuer_chain,
        tcb_info: value.tcb_info,
        tcb_info_signature: value.tcb_info_signature,
        qe_identity_issuer_chain: value.qe_identity_issuer_chain,
        qe_identity: value.qe_identity,
        qe_identity_signature: value.qe_identity_signature,
        pck_certificate_chain: value.pck_certificate_chain,
    }
}

pub fn quote_bytes_to_vec(value: QuoteBytes) -> Vec<u8> {
    value.0
}

pub fn verified_report(value: dq_verify::VerifiedReport) -> VerifiedReport {
    VerifiedReport {
        status: value.status,
        advisory_ids: value.advisory_ids,
        report: report(value.report),
        ppid: value.ppid,
        qe_status: tcb_status_with_advisory(value.qe_status),
        platform_status: tcb_status_with_advisory(value.platform_status),
    }
}

fn report(value: dq_quote::Report) -> Report {
    match value {
        dq_quote::Report::SgxEnclave(r) => Report::SgxEnclave(enclave_report(r)),
        dq_quote::Report::TD10(r) => Report::TD10(td_report_10(r)),
        dq_quote::Report::TD15(r) => Report::TD15(td_report_15(r)),
    }
}

fn td_report_10(value: dq_quote::TDReport10) -> TDReport10 {
    TDReport10 {
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

fn td_report_15(value: dq_quote::TDReport15) -> TDReport15 {
    TDReport15 {
        base: td_report_10(value.base),
        tee_tcb_svn2: value.tee_tcb_svn2,
        mr_service_td: value.mr_service_td,
    }
}

fn enclave_report(value: dq_quote::EnclaveReport) -> EnclaveReport {
    EnclaveReport {
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

fn tcb_status(value: dq_tcb::TcbStatus) -> TcbStatus {
    match value {
        dq_tcb::TcbStatus::UpToDate => TcbStatus::UpToDate,
        dq_tcb::TcbStatus::OutOfDateConfigurationNeeded => TcbStatus::OutOfDateConfigurationNeeded,
        dq_tcb::TcbStatus::OutOfDate => TcbStatus::OutOfDate,
        dq_tcb::TcbStatus::ConfigurationAndSWHardeningNeeded => {
            TcbStatus::ConfigurationAndSWHardeningNeeded
        }
        dq_tcb::TcbStatus::ConfigurationNeeded => TcbStatus::ConfigurationNeeded,
        dq_tcb::TcbStatus::SWHardeningNeeded => TcbStatus::SWHardeningNeeded,
        dq_tcb::TcbStatus::Revoked => TcbStatus::Revoked,
    }
}

fn tcb_status_with_advisory(value: dq_tcb::TcbStatusWithAdvisory) -> TcbStatusWithAdvisory {
    TcbStatusWithAdvisory {
        status: tcb_status(value.status),
        advisory_ids: value.advisory_ids,
    }
}
