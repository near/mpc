//! Attestation-freshness gauges.
//!
//! Both are absolute timestamps rather than remaining durations: a node that stops re-attesting
//! also stops updating them, and only the absolute form keeps decaying towards now, so a staleness
//! alert still fires on a frozen gauge. At rest both advance hourly, as both are read from the
//! entry stored on chain after every submission.

use mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS;
use near_mpc_contract_interface::types::{GetAttestationResponse, VerifiedAttestation};

use crate::metrics::{
    MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS, MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS,
};

const NO_ATTESTATION_STORED: i64 = 0;
const NO_EXPIRY: i64 = -1;

pub(crate) fn record_stored_attestation(stored: Option<&GetAttestationResponse>) {
    MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS.set(expiry_gauge_value(
        stored.map(GetAttestationResponse::attestation),
    ));
    if let Some(landed_at) = stored.and_then(landed_at_seconds) {
        MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS
            .set(i64::try_from(landed_at).unwrap_or(i64::MAX));
    }
}

fn landed_at_seconds(stored: &GetAttestationResponse) -> Option<u64> {
    match stored {
        GetAttestationResponse::Current(stored) => stored.accepted_at_seconds,
        // TODO(#4498): remove once every deployed contract stamps the acceptance time
        GetAttestationResponse::Legacy(attestation) => attestation
            .expiry_timestamp_seconds()
            .and_then(|expiry| expiry.checked_sub(DEFAULT_EXPIRATION_DURATION_SECONDS)),
    }
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
    use near_mpc_contract_interface::types::{MockAttestation, StoredAttestation};
    use rstest::rstest;

    const EXPIRES_AT: u64 = 1_754_000_000;
    const LANDED_AT: u64 = EXPIRES_AT - DEFAULT_EXPIRATION_DURATION_SECONDS;

    fn mock_with_expiry(expiry_timestamp_seconds: Option<u64>) -> VerifiedAttestation {
        VerifiedAttestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds,
            expected_measurements: None,
        })
    }

    fn current(accepted_at_seconds: Option<u64>) -> GetAttestationResponse {
        GetAttestationResponse::Current(StoredAttestation {
            attestation: mock_with_expiry(Some(EXPIRES_AT)),
            accepted_at_seconds,
        })
    }

    #[test]
    fn record_stored_attestation__should_keep_the_last_acceptance_time_for_an_unstamped_entry() {
        // Given
        record_stored_attestation(Some(&current(Some(LANDED_AT))));

        // When
        record_stored_attestation(Some(&current(None)));

        // Then
        assert_eq!(
            (
                MPC_ATTESTATION_EXPIRY_TIMESTAMP_SECONDS.get(),
                MPC_ATTESTATION_LAST_LANDED_TIMESTAMP_SECONDS.get()
            ),
            (EXPIRES_AT as i64, LANDED_AT as i64)
        );
    }

    #[rstest]
    #[case::stamped(current(Some(LANDED_AT)), Some(LANDED_AT))]
    #[case::carried_over_by_the_migration(current(None), None)]
    #[case::legacy_contract(
        GetAttestationResponse::Legacy(mock_with_expiry(Some(EXPIRES_AT))),
        Some(LANDED_AT)
    )]
    #[case::legacy_without_expiry(GetAttestationResponse::Legacy(mock_with_expiry(None)), None)]
    fn landed_at_seconds__should_read_the_acceptance_time(
        #[case] stored: GetAttestationResponse,
        #[case] expected: Option<u64>,
    ) {
        // When
        let landed_at = landed_at_seconds(&stored);

        // Then
        assert_eq!(landed_at, expected);
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
