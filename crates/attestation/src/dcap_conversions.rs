//! Conversions between `dcap_qvl`'s types and the Borsh-mirrored types in
//! `tee-verifier-interface`, for the off-chain `verify_locally` path only.
//!
//! This is an intentional sibling of the identical conversions in the
//! `tee-verifier` contract crate (`tee-verifier/src/conversions.rs`). They
//! are NOT shared through a common crate on purpose: sharing would force the
//! deliberately-minimal verifier contract (`dcap-qvl` + interface only) to
//! depend on `attestation` and drag in its `serde`/`serde_json`/`sha2`/
//! `dstack-sdk-types` closure. Both copies are pinned against `dcap_qvl` drift
//! by their respective byte-equal Borsh-layout tests.
//!
//! Mapped with local `IntoDcapType` / `IntoInterfaceType` traits because
//! the orphan rule forbids `From`/`Into` impls between two foreign types.

use alloc::vec::Vec;
use dcap_qvl::{quote as dq_quote, tcb_info as dq_tcb, verify as dq_verify};
use tee_verifier_interface::{
    Collateral, EnclaveReport, QuoteBytes, Report, TDReport10, TDReport15, TcbStatus,
    TcbStatusWithAdvisory, VerifiedReport,
};

/// Converts an interface type into its `dcap_qvl` counterpart `T`.
pub(crate) trait IntoDcapType<T> {
    fn into_dcap_type(self) -> T;
}

/// Converts a `dcap_qvl` type into its `tee-verifier-interface` counterpart `T`.
pub(crate) trait IntoInterfaceType<T> {
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

/// Converts a `dcap_qvl::QuoteCollateralV3` (e.g. fetched from a PCCS endpoint)
/// into the interface [`Collateral`]. Off-chain helper for callers that hold a
/// `dcap-qvl` collateral and need the wire type.
pub fn collateral_from_dcap(collateral: dcap_qvl::QuoteCollateralV3) -> Collateral {
    collateral.into_interface_type()
}

/// Converts an interface [`Collateral`] into a `dcap_qvl::QuoteCollateralV3`.
/// Off-chain helper, the inverse of [`collateral_from_dcap`].
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
/// against its `dcap_qvl` counterpart, so a same-name field/variant reorder in
/// `dcap_qvl` (which the exhaustive conversions above would not catch) diverges
/// the bytes. Mirrors the test in `tee-verifier/src/conversions.rs`; this is
/// the second pin guarding `attestation`'s own conversion copy.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

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
            pck_crl_issuer_chain: "issuer-chain".into(),
            root_ca_crl: alloc::vec![1, 2, 3],
            pck_crl: alloc::vec![4, 5, 6],
            tcb_info_issuer_chain: "tcb-issuer".into(),
            tcb_info: "tcb-info-json".into(),
            tcb_info_signature: alloc::vec![7, 8],
            qe_identity_issuer_chain: "qe-issuer".into(),
            qe_identity: "qe-identity-json".into(),
            qe_identity_signature: alloc::vec![9, 10],
            pck_certificate_chain: Some("pck-chain".into()),
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
            status: "UpToDate".into(),
            advisory_ids: alloc::vec!["INTEL-SA-00001".into()],
            report,
            ppid: alloc::vec![0xAB; 16],
            qe_status: dq_tcb::TcbStatusWithAdvisory {
                status: dq_tcb::TcbStatus::UpToDate,
                advisory_ids: alloc::vec![],
            },
            platform_status: dq_tcb::TcbStatusWithAdvisory {
                status: dq_tcb::TcbStatus::ConfigurationNeeded,
                advisory_ids: alloc::vec!["INTEL-SA-00002".into()],
            },
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
    #[case::verified(dq_quote::Report::TD10(dcap_td10()))]
    #[case::sgx(dq_quote::Report::SgxEnclave(dcap_sgx()))]
    fn verified_report__should_match_dcap_borsh_layout(#[case] report: dq_quote::Report) {
        let dcap = dcap_verified_report(report);
        let interface: VerifiedReport = dcap.clone().into_interface_type();
        assert_same_borsh_bytes(&interface, &dcap);
    }
}
