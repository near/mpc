//! Conversions between `dcap_qvl`'s types and the Borsh-mirrored types in
//! `tee-verifier-interface`.
//!
//! Shared by the on-chain `tee-verifier` contract and the off-chain
//! `attestation` crate's `verify_locally` path.
//!
//! These mappings need only `dcap-qvl` + `tee-verifier-interface` + `borsh`, so
//! they live in this minimal crate. Putting them in `attestation` instead would
//! force the contract to pull that crate's unrelated dependencies (`serde`,
//! `sha2`, etc.) into its WASM.
//!
//! Mapped with the local [`IntoDcapType`] / [`IntoInterfaceType`] traits. We
//! can not use [`From`] and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

#![no_std]

extern crate alloc;

use alloc::{string::ToString as _, vec::Vec};
use dcap_qvl::{QuoteClaims, quote as dq_quote, tcb_info as dq_tcb, verify as dq_verify};
use tee_verifier_interface::{
    Collateral, CollateralDates, EnclaveReport, QuoteBytes, Report, TDReport10, TDReport15,
    TcbStatus, TcbStatusWithAdvisory, VerifiedReport,
};

/// Converts an interface type into its `dcap_qvl` counterpart `T`.
pub trait IntoDcapType<T> {
    fn into_dcap_type(self) -> T;
}

/// Converts a `dcap_qvl` type into its `tee-verifier-interface` counterpart `T`.
pub trait IntoInterfaceType<T> {
    fn into_interface_type(self) -> T;
}

impl IntoDcapType<dcap_qvl::QuoteCollateralV3> for Collateral {
    fn into_dcap_type(self) -> dcap_qvl::QuoteCollateralV3 {
        dcap_qvl::QuoteCollateralV3 {
            pck_crl_issuer_chain: self.pck_crl_issuer_chain,
            root_ca_crl: self.root_ca_crl,
            pck_crl: self.pck_crl,
            tcb_info_issuer_chain: self.tcb_info_issuer_chain,
            tcb_info: self.tcb_info,
            tcb_info_signature: self.tcb_info_signature,
            qe_identity_issuer_chain: self.qe_identity_issuer_chain,
            qe_identity: self.qe_identity,
            qe_identity_signature: self.qe_identity_signature,
            pck_certificate_chain: self.pck_certificate_chain,
        }
    }
}

impl IntoInterfaceType<Collateral> for dcap_qvl::QuoteCollateralV3 {
    fn into_interface_type(self) -> Collateral {
        Collateral {
            pck_crl_issuer_chain: self.pck_crl_issuer_chain,
            root_ca_crl: self.root_ca_crl,
            pck_crl: self.pck_crl,
            tcb_info_issuer_chain: self.tcb_info_issuer_chain,
            tcb_info: self.tcb_info,
            tcb_info_signature: self.tcb_info_signature,
            qe_identity_issuer_chain: self.qe_identity_issuer_chain,
            qe_identity: self.qe_identity,
            qe_identity_signature: self.qe_identity_signature,
            pck_certificate_chain: self.pck_certificate_chain,
        }
    }
}

pub fn collateral_from_dcap(collateral: dcap_qvl::QuoteCollateralV3) -> Collateral {
    collateral.into_interface_type()
}

pub fn collateral_into_dcap(collateral: Collateral) -> dcap_qvl::QuoteCollateralV3 {
    collateral.into_dcap_type()
}

impl IntoDcapType<Vec<u8>> for QuoteBytes {
    fn into_dcap_type(self) -> Vec<u8> {
        self.0
    }
}

impl IntoInterfaceType<VerifiedReport> for dq_verify::VerifiedReport {
    fn into_interface_type(self) -> VerifiedReport {
        VerifiedReport {
            status: self.status,
            advisory_ids: self.advisory_ids,
            report: self.report.into_interface_type(),
            ppid: self.ppid,
            qe_status: self.qe_status.into_interface_type(),
            platform_status: self.platform_status.into_interface_type(),
        }
    }
}

/// Builds the report the way `dcap_qvl`'s private `into_report_unchecked` does,
/// so it matches what [`dq_verify::verify`] returns for the same quote.
impl IntoInterfaceType<(VerifiedReport, CollateralDates)> for QuoteClaims {
    fn into_interface_type(self) -> (VerifiedReport, CollateralDates) {
        let QuoteClaims {
            claims_version: _,
            header: _,
            tee_type: _,
            tcb,
            platform,
            qe,
            earliest_issue_date,
            latest_issue_date,
            earliest_expiration_date,
            qe_iden_earliest_issue_date,
            qe_iden_latest_issue_date,
            qe_iden_earliest_expiration_date,
            report,
        } = self;
        (
            VerifiedReport {
                status: tcb.status.to_string(),
                advisory_ids: tcb.advisory_ids,
                report: report.into_interface_type(),
                ppid: platform.pck.ppid,
                qe_status: TcbStatusWithAdvisory {
                    status: qe.tcb_level.tcb_status.into_interface_type(),
                    advisory_ids: qe.tcb_level.advisory_ids,
                },
                platform_status: TcbStatusWithAdvisory {
                    status: platform.tcb_level.tcb_status.into_interface_type(),
                    advisory_ids: platform.tcb_level.advisory_ids,
                },
            },
            CollateralDates {
                earliest_issue_date,
                latest_issue_date,
                earliest_expiration_date,
                qe_iden_earliest_issue_date,
                qe_iden_latest_issue_date,
                qe_iden_earliest_expiration_date,
            },
        )
    }
}

impl IntoInterfaceType<Report> for dq_quote::Report {
    fn into_interface_type(self) -> Report {
        match self {
            dq_quote::Report::SgxEnclave(r) => Report::SgxEnclave(r.into_interface_type()),
            dq_quote::Report::TD10(r) => Report::TD10(r.into_interface_type()),
            dq_quote::Report::TD15(r) => Report::TD15(r.into_interface_type()),
        }
    }
}

impl IntoInterfaceType<TDReport10> for dq_quote::TDReport10 {
    fn into_interface_type(self) -> TDReport10 {
        TDReport10 {
            tee_tcb_svn: self.tee_tcb_svn,
            mr_seam: self.mr_seam,
            mr_signer_seam: self.mr_signer_seam,
            seam_attributes: self.seam_attributes,
            td_attributes: self.td_attributes,
            xfam: self.xfam,
            mr_td: self.mr_td,
            mr_config_id: self.mr_config_id,
            mr_owner: self.mr_owner,
            mr_owner_config: self.mr_owner_config,
            rt_mr0: self.rt_mr0,
            rt_mr1: self.rt_mr1,
            rt_mr2: self.rt_mr2,
            rt_mr3: self.rt_mr3,
            report_data: self.report_data,
        }
    }
}

impl IntoInterfaceType<TDReport15> for dq_quote::TDReport15 {
    fn into_interface_type(self) -> TDReport15 {
        TDReport15 {
            base: self.base.into_interface_type(),
            tee_tcb_svn2: self.tee_tcb_svn2,
            mr_service_td: self.mr_service_td,
        }
    }
}

impl IntoInterfaceType<EnclaveReport> for dq_quote::EnclaveReport {
    fn into_interface_type(self) -> EnclaveReport {
        EnclaveReport {
            cpu_svn: self.cpu_svn,
            misc_select: self.misc_select,
            reserved1: self.reserved1,
            attributes: self.attributes,
            mr_enclave: self.mr_enclave,
            reserved2: self.reserved2,
            mr_signer: self.mr_signer,
            reserved3: self.reserved3,
            isv_prod_id: self.isv_prod_id,
            isv_svn: self.isv_svn,
            reserved4: self.reserved4,
            report_data: self.report_data,
        }
    }
}

impl IntoInterfaceType<TcbStatus> for dq_tcb::TcbStatus {
    fn into_interface_type(self) -> TcbStatus {
        match self {
            dq_tcb::TcbStatus::UpToDate => TcbStatus::UpToDate,
            dq_tcb::TcbStatus::OutOfDateConfigurationNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            }
            dq_tcb::TcbStatus::OutOfDate => TcbStatus::OutOfDate,
            dq_tcb::TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::ConfigurationAndSWHardeningNeeded
            }
            dq_tcb::TcbStatus::ConfigurationNeeded => TcbStatus::ConfigurationNeeded,
            dq_tcb::TcbStatus::SWHardeningNeeded => TcbStatus::SWHardeningNeeded,
            dq_tcb::TcbStatus::Revoked => TcbStatus::Revoked,
        }
    }
}

impl IntoInterfaceType<TcbStatusWithAdvisory> for dq_tcb::TcbStatusWithAdvisory {
    fn into_interface_type(self) -> TcbStatusWithAdvisory {
        TcbStatusWithAdvisory {
            status: self.status.into_interface_type(),
            advisory_ids: self.advisory_ids,
        }
    }
}

/// Pins the Borsh wire layout of each `tee-verifier-interface` mirror type
/// against its `dcap_qvl` counterpart.
///
/// The conversions above already make the compiler reject an upstream rename,
/// removal, type change, or added variant; the drift they miss is a same-name
/// *reordering* of fields or variants, which silently changes the Borsh layout.
/// Each test builds both sides by the same field/variant names and asserts
/// equal Borsh bytes, so a reorder diverges — even for fieldless enum variants.
/// This relies on every field having a distinct fill value (`[1; _]`, `[2; _]`,
/// ...): a swap of two same-typed fields is only observable when they differ.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use rstest::rstest;

    /// Asserts the two values encode to identical Borsh bytes.
    fn assert_same_borsh_bytes<I: borsh::BorshSerialize, D: borsh::BorshSerialize>(
        interface: &I,
        dcap: &D,
    ) {
        let interface_bytes = borsh::to_vec(interface).expect("interface should serialize");
        let dcap_bytes = borsh::to_vec(dcap).expect("dcap should serialize");
        assert_eq!(interface_bytes, dcap_bytes);
    }

    fn sample_collateral() -> Collateral {
        Collateral {
            pck_crl_issuer_chain: "issuer-chain".to_string(),
            root_ca_crl: vec![1, 2, 3],
            pck_crl: vec![4, 5, 6],
            tcb_info_issuer_chain: "tcb-issuer".to_string(),
            tcb_info: "tcb-info-json".to_string(),
            tcb_info_signature: vec![7, 8],
            qe_identity_issuer_chain: "qe-issuer".to_string(),
            qe_identity: "qe-identity-json".to_string(),
            qe_identity_signature: vec![9, 10],
            pck_certificate_chain: Some("pck-chain".to_string()),
        }
    }

    fn dcap_td10() -> dq_quote::TDReport10 {
        dq_quote::TDReport10 {
            tee_tcb_svn: [1; 16],
            mr_seam: [2; 48],
            mr_signer_seam: [3; 48],
            seam_attributes: [4; 8],
            td_attributes: [5; 8],
            xfam: [6; 8],
            mr_td: [7; 48],
            mr_config_id: [8; 48],
            mr_owner: [9; 48],
            mr_owner_config: [10; 48],
            rt_mr0: [11; 48],
            rt_mr1: [12; 48],
            rt_mr2: [13; 48],
            rt_mr3: [14; 48],
            report_data: [15; 64],
        }
    }

    fn dcap_td15() -> dq_quote::TDReport15 {
        dq_quote::TDReport15 {
            base: dcap_td10(),
            tee_tcb_svn2: [16; 16],
            mr_service_td: [17; 48],
        }
    }

    fn dcap_sgx() -> dq_quote::EnclaveReport {
        dq_quote::EnclaveReport {
            cpu_svn: [1; 16],
            misc_select: 42,
            reserved1: [2; 28],
            attributes: [3; 16],
            mr_enclave: [4; 32],
            reserved2: [5; 32],
            mr_signer: [6; 32],
            reserved3: [7; 96],
            isv_prod_id: 8,
            isv_svn: 9,
            reserved4: [10; 60],
            report_data: [11; 64],
        }
    }

    fn dcap_verified_report(report: dq_quote::Report) -> dq_verify::VerifiedReport {
        dq_verify::VerifiedReport {
            status: "UpToDate".to_string(),
            advisory_ids: vec!["INTEL-SA-00001".to_string()],
            report,
            ppid: vec![0xAB; 16],
            qe_status: dq_tcb::TcbStatusWithAdvisory {
                status: dq_tcb::TcbStatus::UpToDate,
                advisory_ids: vec![],
            },
            platform_status: dq_tcb::TcbStatusWithAdvisory {
                status: dq_tcb::TcbStatus::ConfigurationNeeded,
                advisory_ids: vec!["INTEL-SA-00002".to_string()],
            },
        }
    }

    /// Name-equal `dcap_qvl` counterpart of an interface [`TcbStatus`]. The
    /// exhaustive `match` makes the compiler flag an upstream variant
    /// rename/removal; the byte comparison in the test catches a reorder.
    fn dcap_tcb_status(status: &TcbStatus) -> dq_tcb::TcbStatus {
        match status {
            TcbStatus::UpToDate => dq_tcb::TcbStatus::UpToDate,
            TcbStatus::OutOfDateConfigurationNeeded => {
                dq_tcb::TcbStatus::OutOfDateConfigurationNeeded
            }
            TcbStatus::OutOfDate => dq_tcb::TcbStatus::OutOfDate,
            TcbStatus::ConfigurationAndSWHardeningNeeded => {
                dq_tcb::TcbStatus::ConfigurationAndSWHardeningNeeded
            }
            TcbStatus::ConfigurationNeeded => dq_tcb::TcbStatus::ConfigurationNeeded,
            TcbStatus::SWHardeningNeeded => dq_tcb::TcbStatus::SWHardeningNeeded,
            TcbStatus::Revoked => dq_tcb::TcbStatus::Revoked,
        }
    }

    #[test]
    fn collateral__should_match_dcap_borsh_layout() {
        let interface = sample_collateral();
        let dcap = interface.clone().into_dcap_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    #[test]
    fn td_report_10__should_match_dcap_borsh_layout() {
        let dcap = dcap_td10();
        let interface: TDReport10 = dcap.into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    #[test]
    fn td_report_15__should_match_dcap_borsh_layout() {
        let dcap = dcap_td15();
        let interface: TDReport15 = dcap.into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    #[test]
    fn enclave_report__should_match_dcap_borsh_layout() {
        let dcap = dcap_sgx();
        let interface: EnclaveReport = dcap.into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    #[rstest]
    #[case::sgx(dq_quote::Report::SgxEnclave(dcap_sgx()))]
    #[case::td10(dq_quote::Report::TD10(dcap_td10()))]
    #[case::td15(dq_quote::Report::TD15(dcap_td15()))]
    fn report__should_match_dcap_borsh_layout(#[case] dcap: dq_quote::Report) {
        let interface: Report = dcap.clone().into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    #[rstest]
    #[case(TcbStatus::UpToDate)]
    #[case(TcbStatus::OutOfDateConfigurationNeeded)]
    #[case(TcbStatus::OutOfDate)]
    #[case(TcbStatus::ConfigurationAndSWHardeningNeeded)]
    #[case(TcbStatus::ConfigurationNeeded)]
    #[case(TcbStatus::SWHardeningNeeded)]
    #[case(TcbStatus::Revoked)]
    fn tcb_status__should_match_dcap_borsh_layout(#[case] status: TcbStatus) {
        let dcap = dcap_tcb_status(&status);
        assert_same_borsh_bytes(&status, &dcap);
    }

    #[test]
    fn tcb_status_with_advisory__should_match_dcap_borsh_layout() {
        let dcap = dq_tcb::TcbStatusWithAdvisory {
            status: dq_tcb::TcbStatus::ConfigurationNeeded,
            advisory_ids: vec!["INTEL-SA-00003".to_string()],
        };
        let interface: TcbStatusWithAdvisory = dcap.clone().into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }

    fn dcap_tcb_level(status: dq_tcb::TcbStatus, advisory_id: &str) -> dq_tcb::TcbLevel {
        dq_tcb::TcbLevel {
            tcb: dq_tcb::Tcb {
                sgx_components: vec![],
                tdx_components: vec![],
                pce_svn: 0,
            },
            tcb_date: "2026-01-01T00:00:00Z".to_string(),
            tcb_status: status,
            advisory_ids: vec![advisory_id.to_string()],
        }
    }

    /// Every field the conversion reads holds a distinct value, so a swap of
    /// two same-typed fields changes the output.
    fn dcap_quote_claims() -> QuoteClaims {
        QuoteClaims {
            claims_version: 1,
            header: dq_quote::Header {
                version: 4,
                attestation_key_type: 2,
                tee_type: 0x81,
                qe_svn: 0,
                pce_svn: 0,
                qe_vendor_id: [0; 16],
                user_data: [0; 20],
            },
            tee_type: 0x81,
            tcb: dcap_qvl::TcbVerdict {
                status: dq_tcb::TcbStatus::OutOfDate,
                advisory_ids: vec!["INTEL-SA-00001".to_string()],
                eval_data_number: 0,
            },
            platform: dcap_qvl::PlatformInfo {
                tcb_level: dcap_tcb_level(dq_tcb::TcbStatus::ConfigurationNeeded, "INTEL-SA-00002"),
                tcb_date_tag: 0,
                pck: dcap_qvl::PckIdentity {
                    ppid: vec![0xAB; 16],
                    cpu_svn: [0; 16],
                    pce_svn: 0,
                    pce_id: vec![],
                    fmspc: [0; 6],
                    sgx_type: 0,
                    platform_instance_id: None,
                    dynamic_platform: dcap_qvl::PckCertFlag::Undefined,
                    cached_keys: dcap_qvl::PckCertFlag::Undefined,
                    smt_enabled: dcap_qvl::PckCertFlag::Undefined,
                    platform_provider_id: None,
                },
                root_key_id: vec![],
                pck_crl_num: 0,
                root_ca_crl_num: 0,
            },
            qe: dcap_qvl::QeInfo {
                tcb_level: dcap_qvl::QeTcbLevel {
                    tcb: dcap_qvl::QeTcb { isvsvn: 0 },
                    tcb_date: "2026-01-01T00:00:00Z".to_string(),
                    tcb_status: dq_tcb::TcbStatus::SWHardeningNeeded,
                    advisory_ids: vec!["INTEL-SA-00003".to_string()],
                },
                report: dcap_sgx(),
                tcb_eval_data_number: 0,
            },
            earliest_issue_date: 1,
            latest_issue_date: 2,
            earliest_expiration_date: 3,
            qe_iden_earliest_issue_date: 4,
            qe_iden_latest_issue_date: 5,
            qe_iden_earliest_expiration_date: 6,
            report: dq_quote::Report::TD10(dcap_td10()),
        }
    }

    #[test]
    fn quote_claims__should_convert_to_verified_report_and_collateral_dates() {
        // Given
        let claims = dcap_quote_claims();

        // When
        let result = claims.into_interface_type();

        // Then
        let expected = (
            VerifiedReport {
                status: "OutOfDate".to_string(),
                advisory_ids: vec!["INTEL-SA-00001".to_string()],
                report: Report::TD10(dcap_td10().into_interface_type()),
                ppid: vec![0xAB; 16],
                qe_status: TcbStatusWithAdvisory {
                    status: TcbStatus::SWHardeningNeeded,
                    advisory_ids: vec!["INTEL-SA-00003".to_string()],
                },
                platform_status: TcbStatusWithAdvisory {
                    status: TcbStatus::ConfigurationNeeded,
                    advisory_ids: vec!["INTEL-SA-00002".to_string()],
                },
            },
            CollateralDates {
                earliest_issue_date: 1,
                latest_issue_date: 2,
                earliest_expiration_date: 3,
                qe_iden_earliest_issue_date: 4,
                qe_iden_latest_issue_date: 5,
                qe_iden_earliest_expiration_date: 6,
            },
        );
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::sgx(dq_quote::Report::SgxEnclave(dcap_sgx()))]
    #[case::td10(dq_quote::Report::TD10(dcap_td10()))]
    #[case::td15(dq_quote::Report::TD15(dcap_td15()))]
    fn verified_report__should_match_dcap_borsh_layout(#[case] report: dq_quote::Report) {
        let dcap = dcap_verified_report(report);
        let interface: VerifiedReport = dcap.clone().into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }
}
