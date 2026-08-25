//! Attestation-freshness gauges.
//!
//! Both are absolute timestamps rather than remaining durations: a node that stops re-attesting
//! also stops updating them, and only the absolute form keeps decaying towards now, so a staleness
//! alert still fires on a frozen gauge. Each landed submission moves them, so at rest they
//! advance hourly.

use near_mpc_contract_interface::types::VerifiedAttestation;
use near_time::Clock;

use crate::metrics::{
    MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS, MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS,
};

const NO_ATTESTATION_STORED: i64 = 0;
const NO_EXPIRY: i64 = -1;

pub(crate) fn record_stored_attestation_expiry(stored: Option<&VerifiedAttestation>) {
    MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS.set(expiry_gauge_value(stored));
}

pub(crate) fn record_attestation_landed() {
    MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS.set(Clock::real().now_utc().unix_timestamp());
}

fn expiry_gauge_value(stored: Option<&VerifiedAttestation>) -> i64 {
    match stored.map(VerifiedAttestation::expiry_timestamp_seconds) {
        None => NO_ATTESTATION_STORED,
        Some(None) => NO_EXPIRY,
        Some(Some(expiry)) => i64::try_from(expiry).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_contract_interface::types::MockAttestation;
    use rstest::rstest;

    const EXPIRES_AT: u64 = 1_754_000_000;

    fn mock_with_expiry(expiry_timestamp_seconds: Option<u64>) -> VerifiedAttestation {
        VerifiedAttestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds,
            expected_measurements: None,
        })
    }

    #[rstest]
    #[case::nothing_stored(None, NO_ATTESTATION_STORED)]
    #[case::stored_with_expiry(Some(mock_with_expiry(Some(EXPIRES_AT))), EXPIRES_AT as i64)]
    #[case::stored_without_expiry(Some(mock_with_expiry(None)), NO_EXPIRY)]
    #[case::unstamped_mock(Some(VerifiedAttestation::Mock(MockAttestation::Valid)), NO_EXPIRY)]
    #[case::expiry_beyond_i64(Some(mock_with_expiry(Some(u64::MAX))), i64::MAX)]
    fn expiry_gauge_value__should_report_stored_expiry_or_a_sentinel(
        #[case] stored: Option<VerifiedAttestation>,
        #[case] expected: i64,
    ) {
        // When
        let value = expiry_gauge_value(stored.as_ref());

        // Then
        assert_eq!(value, expected);
    }
}
