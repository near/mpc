use dcap_qvl::verify::VerifiedReport;
use derive_more::Constructor;

use crate::{
    collateral::Collateral, hash::MpcDockerImageHash, quote::Quote, report_data::ReportData,
    tcbinfo::TcbInfo,
};
use near_sdk::PublicKey;

/// Expected status for a successfully verified TEE quote.
const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

#[allow(clippy::large_enum_variant)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Local(LocalAttestation),
}

#[allow(dead_code)]
#[derive(Constructor)]
pub struct DstackAttestation {
    quote: Quote,
    collateral: Collateral,
    tcb_info: TcbInfo,
}

#[derive(Constructor)]
pub struct LocalAttestation {
    quote_verification_result: bool,
    docker_image_verification_result: bool,
}

impl Attestation {
    pub fn verify_quote(&self, expected_report_data: ReportData, timestamp_s: u64) -> bool {
        match self {
            Self::Dstack(dstack_attestation) => {
                self.verify_tee_quote(dstack_attestation, expected_report_data, timestamp_s)
            }
            Self::Local(config) => config.quote_verification_result,
        }
    }

    fn verify_tee_quote(
        &self,
        attestation: &DstackAttestation,
        expected_report_data: ReportData,
        timestamp_s: u64,
    ) -> bool {
        let quote_bytes = attestation.quote.raw_bytes();

        match dcap_qvl::verify::verify(quote_bytes, &attestation.collateral, timestamp_s) {
            Ok(verification_result) => {
                let status_is_up_to_date = verification_result.status == EXPECTED_QUOTE_STATUS;

                // Advisory IDs indicate known security vulnerabilities or issues with the TEE.
                // For a quote to be considered secure, there should be no outstanding advisories.
                let no_security_advisories = verification_result.advisory_ids.is_empty();

                let report_data_valid =
                    if let Some(actual_report_data) = verification_result.report.as_td10() {
                        expected_report_data.to_bytes() == actual_report_data.report_data
                    } else {
                        tracing::error!(
                            "Expected TD10 report data, but got: {:?}",
                            verification_result.report
                        );
                        false
                    };

                status_is_up_to_date && no_security_advisories && report_data_valid
            }
            Err(err) => {
                tracing::error!("TEE quote verification failed: {:?}", err);
                false
            }
        }
    }

    // TODO(#643): Implement the Docker image verification logic in the attestation module
    pub fn verify_docker_image(
        &self,
        _allowed_docker_image_hashes: &[MpcDockerImageHash],
        _historical_docker_image_hashes: &[MpcDockerImageHash],
        _measurements: Measurements,
        _public_key: PublicKey,
    ) -> bool {
        match self {
            Self::Dstack(_config) => {
                todo!("Implement Docker image validation logic")
            }
            Self::Local(config) => config.docker_image_verification_result,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    rt_mr0: [u8; 48],
    rt_mr1: [u8; 48],
    rt_mr2: [u8; 48],
    rt_td: [u8; 48],
}

#[derive(Debug)]
pub enum MeasurementsError {
    NoTd10Report,
}

impl TryFrom<VerifiedReport> for Measurements {
    type Error = MeasurementsError;

    fn try_from(verified_report: VerifiedReport) -> Result<Self, Self::Error> {
        let td10 = verified_report
            .report
            .as_td10()
            .ok_or(MeasurementsError::NoTd10Report)?;
        Ok(Self {
            rt_mr0: td10.rt_mr0,
            rt_mr1: td10.rt_mr1,
            rt_mr2: td10.rt_mr2,
            rt_td: td10.mr_td,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::report_data::ReportDataV1;

    use super::*;
    use rstest::rstest;

    fn mock_attestation(
        quote_verification_result: bool,
        docker_image_verification_result: bool,
    ) -> Attestation {
        Attestation::Local(LocalAttestation {
            quote_verification_result,
            docker_image_verification_result,
        })
    }

    #[rstest]
    #[case(false, false, false)]
    #[case(false, true, false)]
    #[case(true, false, true)]
    #[case(true, true, true)]
    fn test_mock_attestation_verify_quote(
        #[case] quote_verification_result: bool,
        #[case] docker_image_verification_result: bool,
        #[case] expected_quote_verification_result: bool,
    ) {
        let timestamp_s = 0u64;
        let tls_key = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"
            .parse()
            .unwrap();
        let account_key = "ed25519:H9k5eiU4xXyb8F7cUDjZYNuH1zGAx5BBNrYwLPNhq6Zx"
            .parse()
            .unwrap();
        let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

        assert_eq!(
            mock_attestation(quote_verification_result, docker_image_verification_result)
                .verify_quote(report_data, timestamp_s),
            expected_quote_verification_result
        );
    }

    #[rstest]
    #[case(false, false, false)]
    #[case(false, true, true)]
    #[case(true, false, false)]
    #[case(true, true, true)]
    // TODO(#643): Test docker image verification logic
    fn test_mock_attestation_verify_docker_image(
        #[case] quote_verification_result: bool,
        #[case] docker_image_verification_result: bool,
        #[case] expected: bool,
    ) {
        let measurements = Measurements {
            rt_mr0: [0u8; 48],
            rt_mr1: [0u8; 48],
            rt_mr2: [0u8; 48],
            rt_td: [0u8; 48],
        };
        let key: PublicKey = "ed25519:9Tfe2FVj6nv2Y7R9NZynD46Nqb8LKRyVZjPgJVSKKxoR"
            .parse()
            .unwrap();

        assert_eq!(
            mock_attestation(quote_verification_result, docker_image_verification_result)
                .verify_docker_image(&[], &[], measurements, key),
            expected
        );
    }
}
