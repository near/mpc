//! Borsh DTOs spoken at the `tee-verifier` contract boundary.
//!
//! Field-for-field mirrors of the `dcap_qvl` input and output types,
//! owned here so the Borsh wire layout is independent of upstream.
//!
//! It is the only DTO crate a consumer (`mpc-contract` and future external
//! contracts) needs to talk to the verifier, without linking `dcap-qvl` into
//! its own WASM. `no_std`, no `dcap-qvl` dependency; the `dcap_qvl` conversions
//! live in `tee-verifier-conversions`.

#![no_std]

extern crate alloc;

#[cfg(feature = "borsh-schema")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};

/// Raw bytes of an Intel TDX / SGX quote, as produced by the platform.
///
/// The verifier expects the same byte layout that `dcap_qvl::verify::verify`
/// expects as its first argument.
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    derive_more::From,
    derive_more::Into,
)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
// The off-by-default `serde` feature is for off-chain callers that embed the
// verifier *input* types (`QuoteBytes`, `Collateral`) in serde structs. The
// Borsh cross-contract ABI never enables it; the report/output types stay
// Borsh-only.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QuoteBytes(pub Vec<u8>);

/// Quote collateral, mirroring `dcap_qvl::QuoteCollateralV3`.
///
/// Field-for-field copy so the wire layout matches the upstream Borsh
/// encoding of `QuoteCollateralV3`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
// See the note on [`QuoteBytes`]: the off-by-default `serde` feature is for
// off-chain callers only and covers just the verifier input types.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: Vec<u8>,
    pub pck_certificate_chain: Option<String>,
}

/// Verified TDX quote, mirroring `dcap_qvl::verify::VerifiedReport`.
///
/// All fields match the upstream type one-to-one.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    pub ppid: Vec<u8>,
    pub qe_status: TcbStatusWithAdvisory,
    pub platform_status: TcbStatusWithAdvisory,
}

/// Parsed quote report, mirroring `dcap_qvl::quote::Report`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub enum Report {
    SgxEnclave(EnclaveReport),
    TD10(TDReport10),
    TD15(TDReport15),
}

impl Report {
    /// Mirrors `dcap_qvl::quote::Report::as_td10`: returns the TD10 view of
    /// either a `TD10` or a `TD15` report.
    pub fn as_td10(&self) -> Option<&TDReport10> {
        match self {
            Report::TD10(report) => Some(report),
            Report::TD15(report) => Some(&report.base),
            Report::SgxEnclave(_) => None,
        }
    }
}

/// Mirror of `dcap_qvl::quote::TDReport10`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct TDReport10 {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rt_mr0: [u8; 48],
    pub rt_mr1: [u8; 48],
    pub rt_mr2: [u8; 48],
    pub rt_mr3: [u8; 48],
    pub report_data: [u8; 64],
}

/// Mirror of `dcap_qvl::quote::TDReport15`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct TDReport15 {
    pub base: TDReport10,
    pub tee_tcb_svn2: [u8; 16],
    pub mr_service_td: [u8; 48],
}

/// Mirror of `dcap_qvl::quote::EnclaveReport`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    pub reserved1: [u8; 28],
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    pub reserved3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub reserved4: [u8; 60],
    pub report_data: [u8; 64],
}

/// Mirror of `dcap_qvl::tcb_info::TcbStatus`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub enum TcbStatus {
    UpToDate,
    OutOfDateConfigurationNeeded,
    OutOfDate,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    SWHardeningNeeded,
    Revoked,
}

/// Mirror of `dcap_qvl::tcb_info::TcbStatusWithAdvisory`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct TcbStatusWithAdvisory {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

/// Verifier-side rejection of a quote, carried inside
/// [`VerificationResult::Rejected`]. A wire DTO: it travels in a successful
/// receipt payload so an on-chain caller can read the reason.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, derive_more::Display)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub enum VerifierError {
    /// `dcap_qvl::verify::verify` rejected the quote / collateral.
    #[display("dcap verification failed: {_0}")]
    DcapVerification(String),
}

/// Outcome of `verify_quote`, returned as the value of a successful receipt
/// (not via `#[handle_result]`). A rejection is therefore `Rejected(..)`, which
/// a caller can tell apart from `PromiseError::Failed` ("verifier down"); a
/// failed receipt carries no payload and would conflate the two.
#[expect(clippy::large_enum_variant)]
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub enum VerificationResult {
    /// The quote verified successfully against the supplied collateral.
    Verified(VerifiedReport),
    /// The verifier ran and rejected the quote.
    Rejected(VerifierError),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use rstest::rstest;

    fn sample_td10() -> TDReport10 {
        TDReport10 {
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

    fn sample_td15() -> TDReport15 {
        TDReport15 {
            base: sample_td10(),
            tee_tcb_svn2: [16; 16],
            mr_service_td: [17; 48],
        }
    }

    fn sample_sgx() -> EnclaveReport {
        EnclaveReport {
            cpu_svn: [1; 16],
            misc_select: 42,
            reserved1: [0; 28],
            attributes: [2; 16],
            mr_enclave: [3; 32],
            reserved2: [0; 32],
            mr_signer: [4; 32],
            reserved3: [0; 96],
            isv_prod_id: 1,
            isv_svn: 2,
            reserved4: [0; 60],
            report_data: [5; 64],
        }
    }

    fn sample_verified_report(report: Report) -> VerifiedReport {
        VerifiedReport {
            status: String::from("UpToDate"),
            advisory_ids: vec![String::from("INTEL-SA-00001")],
            report,
            ppid: vec![0xAB; 16],
            qe_status: TcbStatusWithAdvisory {
                status: TcbStatus::UpToDate,
                advisory_ids: vec![],
            },
            platform_status: TcbStatusWithAdvisory {
                status: TcbStatus::ConfigurationNeeded,
                advisory_ids: vec![String::from("INTEL-SA-00002")],
            },
        }
    }

    #[rstest]
    #[case::td10(Report::TD10(sample_td10()))]
    #[case::td15(Report::TD15(sample_td15()))]
    #[case::sgx(Report::SgxEnclave(sample_sgx()))]
    fn verified_report__should_round_trip_borsh(#[case] report: Report) {
        // Given
        let original = sample_verified_report(report);

        // When
        let bytes = borsh::to_vec(&original).expect("Borsh serialization should succeed");
        let decoded: VerifiedReport =
            borsh::from_slice(&bytes).expect("Borsh deserialization should succeed");

        // Then
        assert_eq!(original, decoded);
    }

    #[test]
    fn as_td10__should_return_td15_base() {
        // Given
        let base = sample_td10();
        let td15 = Report::TD15(TDReport15 {
            base: base.clone(),
            tee_tcb_svn2: [0; 16],
            mr_service_td: [0; 48],
        });

        // When
        let unwrapped = td15.as_td10();

        // Then
        assert_eq!(unwrapped, Some(&base));
    }

    #[test]
    fn as_td10__should_return_td10_itself() {
        // Given
        let td10 = sample_td10();
        let report = Report::TD10(td10.clone());

        // When
        let unwrapped = report.as_td10();

        // Then
        assert_eq!(unwrapped, Some(&td10));
    }

    #[test]
    fn as_td10__should_return_none_for_sgx() {
        // Given
        let report = Report::SgxEnclave(sample_sgx());

        // When
        let unwrapped = report.as_td10();

        // Then
        assert_eq!(unwrapped, None);
    }

    #[rstest]
    #[case(TcbStatus::UpToDate)]
    #[case(TcbStatus::OutOfDateConfigurationNeeded)]
    #[case(TcbStatus::OutOfDate)]
    #[case(TcbStatus::ConfigurationAndSWHardeningNeeded)]
    #[case(TcbStatus::ConfigurationNeeded)]
    #[case(TcbStatus::SWHardeningNeeded)]
    #[case(TcbStatus::Revoked)]
    fn tcb_status__should_round_trip_borsh(#[case] status: TcbStatus) {
        // Given
        let original = status;

        // When
        let bytes = borsh::to_vec(&original).expect("Borsh serialization should succeed");
        let decoded: TcbStatus =
            borsh::from_slice(&bytes).expect("Borsh deserialization should succeed");

        // Then
        assert_eq!(original, decoded);
    }

    #[test]
    fn collateral__should_round_trip_borsh() {
        // Given
        let original = Collateral {
            pck_crl_issuer_chain: String::from("issuer-chain"),
            root_ca_crl: vec![1, 2, 3],
            pck_crl: vec![4, 5, 6],
            tcb_info_issuer_chain: String::from("tcb-issuer"),
            tcb_info: String::from("tcb-info-json"),
            tcb_info_signature: vec![7, 8],
            qe_identity_issuer_chain: String::from("qe-issuer"),
            qe_identity: String::from("qe-identity-json"),
            qe_identity_signature: vec![9, 10],
            pck_certificate_chain: Some(String::from("pck-chain")),
        };

        // When
        let bytes = borsh::to_vec(&original).expect("Borsh serialization should succeed");
        let decoded: Collateral =
            borsh::from_slice(&bytes).expect("Borsh deserialization should succeed");

        // Then
        assert_eq!(original, decoded);
    }

    #[rstest]
    #[case::verified(VerificationResult::Verified(sample_verified_report(Report::TD10(
        sample_td10()
    ))))]
    #[case::rejected(VerificationResult::Rejected(VerifierError::DcapVerification(
        String::from("TCB status is invalid")
    )))]
    fn verification_result__should_round_trip_borsh(#[case] original: VerificationResult) {
        // When
        let bytes = borsh::to_vec(&original).expect("Borsh serialization should succeed");
        let decoded: VerificationResult =
            borsh::from_slice(&bytes).expect("Borsh deserialization should succeed");

        // Then
        assert_eq!(original, decoded);
    }

    #[test]
    fn verifier_error__should_display_reason() {
        // Given
        let err = VerifierError::DcapVerification(String::from("Fmspc mismatch"));

        // When
        let rendered = err.to_string();

        // Then
        assert_eq!(rendered, "dcap verification failed: Fmspc mismatch");
    }

    #[test]
    fn quote_bytes__should_round_trip_borsh() {
        // Given
        let original = QuoteBytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // When
        let bytes = borsh::to_vec(&original).expect("Borsh serialization should succeed");
        let decoded: QuoteBytes =
            borsh::from_slice(&bytes).expect("Borsh deserialization should succeed");

        // Then
        assert_eq!(original, decoded);
    }

    #[test]
    fn quote_bytes__should_convert_to_and_from_vec() {
        // Given
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // When
        let quote = QuoteBytes::from(bytes.clone());
        let round_tripped: Vec<u8> = quote.clone().into();

        // Then
        assert_eq!(quote, QuoteBytes(bytes.clone()));
        assert_eq!(round_tripped, bytes);
    }
}
