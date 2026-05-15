use assert_matches::assert_matches;
use attestation::attestation::DstackVerify as _;
use attestation_types::measurements::{ExpectedMeasurements, Measurements};
use attestation_types::verify_post_dcap::VerificationError;
use mpc_attestation::attestation::{
    Attestation, DEFAULT_EXPIRATION_DURATION_SECONDS, MockAttestation, VerifiedAttestation,
    default_measurements,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use test_utils::attestation::{
    VALID_ATTESTATION_TIMESTAMP, account_key, image_digest, launcher_compose_digest,
    mock_dstack_attestation, p2p_tls_key,
};

/// Off-chain convenience: runs the full dcap-qvl + post-DCAP path in
/// one call. Mirrors what the deleted `Attestation::verify` method used
/// to do. Lives here because `mpc-attestation` no longer depends on
/// the `dcap-qvl`-using `attestation` crate.
fn local_verify(
    attestation: &Attestation,
    expected_report_data: ReportData,
    timestamp_seconds: u64,
    allowed_mpc_docker_image_hashes: &[NodeImageHash],
    allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    accepted_measurements: &[ExpectedMeasurements],
) -> Result<VerifiedAttestation, VerificationError> {
    let verified_report = match attestation {
        Attestation::Dstack(dstack) => {
            let measurements = dstack.verify(
                expected_report_data.clone(),
                timestamp_seconds,
                accepted_measurements,
            )?;
            // `DstackVerify::verify` already ran the post-DCAP checks
            // for us, including measurement matching. We still need a
            // `VerifiedReport` to pass into `finish_verify` (which
            // re-runs the same checks) — build it by re-calling the
            // local conversion. This path is off-chain and the double
            // work is negligible.
            //
            // The simpler alternative would be to factor a `verify_raw`
            // out of `attestation` that returns the mirror report
            // directly. For test code, this is fine; production callers
            // (the `mpc-contract` Promise callback) get the mirror
            // directly from the verifier contract.
            let _ = measurements;
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

/// Calls `dcap_qvl::verify::verify` against a `DstackAttestation` and
/// returns the result as the Borsh mirror.
fn local_dcap_verify(
    dstack: &mpc_attestation::attestation::DstackAttestation,
    timestamp_seconds: u64,
) -> Result<tee_verifier_interface::VerifiedReport, VerificationError> {
    let collateral = attestation::collateral_to_dcap(dstack.collateral.clone());
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
            dcap_qvl::quote::Report::SgxEnclave(_) => unreachable!("SGX not used in tests"),
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

/// Zero-valued `VerifiedReport` for `Mock` paths that ignore it.
fn zero_verified_report() -> tee_verifier_interface::VerifiedReport {
    tee_verifier_interface::VerifiedReport {
        status: String::new(),
        advisory_ids: Vec::new(),
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
        ppid: Vec::new(),
        qe_status: tee_verifier_interface::TcbStatusWithAdvisory {
            status: tee_verifier_interface::TcbStatus::UpToDate,
            advisory_ids: Vec::new(),
        },
        platform_status: tee_verifier_interface::TcbStatusWithAdvisory {
            status: tee_verifier_interface::TcbStatus::UpToDate,
            advisory_ids: Vec::new(),
        },
    }
}

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        local_verify(&valid_attestation, report_data, timestamp_s, &[], &[], &[]),
        Ok(VerifiedAttestation::Mock(MockAttestation::Valid))
    );
}

#[test]
fn invalid_mock_attestation_fails_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Invalid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        local_verify(&valid_attestation, report_data, timestamp_s, &[], &[], &[]),
        Err(VerificationError::InvalidMockAttestation)
    );
}

#[test]
fn validated_dstack_attestation_can_be_reverified() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = local_verify(
        &attestation,
        report_data,
        timestamp_s,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification failed");

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    // then
    assert_matches!(re_verification_result, Ok(()));
}

#[test]
fn validated_dstack_attestation_fails_reverification_when_expired() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = local_verify(
        &attestation,
        report_data,
        timestamp_s,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification failed");

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS + 1,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    // then
    assert_matches!(
        re_verification_result,
        Err(VerificationError::Custom(msg)) if msg.contains("The attestation expired")
    );
}

#[test]
fn validated_mock_attestation_passes_reverification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();

    let validated = local_verify(&valid_attestation, report_data, 0, &[], &[], &[])
        .expect("Initial verification failed");

    // Mock should generally pass re-verify
    assert_matches!(validated.re_verify(100, &[], &[], &[]), Ok(()));
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_rotated_hashes() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;

    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    // 1. Initial verify succeeds with the "old" allowed list
    let validated = local_verify(
        &attestation,
        report_data,
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification should succeed");

    let new_allowed_mpc_docker_image_hashes = [[42; 32].into()];

    // 2. Re-verify fails if we remove the allowed hash (e.g. strict rotation)
    let result = validated.re_verify(
        creation_time,
        &new_allowed_mpc_docker_image_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("not in the allowed hashes list")
    );
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_removed_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = local_verify(
        &attestation,
        report_data,
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification should succeed");

    let different_measurements = [ExpectedMeasurements {
        rtmrs: Measurements {
            mrtd: [0xAA; 48],
            rtmr0: [0xBB; 48],
            rtmr1: [0xCC; 48],
            rtmr2: [0xDD; 48],
        },
        key_provider_event_digest: [0xEE; 48],
    }];

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &different_measurements,
    );

    // then
    assert_matches!(result, Err(VerificationError::MeasurementsNotAllowed));
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_empty_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = local_verify(
        &attestation,
        report_data,
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification should succeed");

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &[],
    );

    // then
    assert_matches!(result, Err(VerificationError::EmptyMeasurementsList));
}

#[test]
fn validated_dstack_attestation_passes_reverification_with_superset_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = local_verify(
        &attestation,
        report_data,
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    )
    .expect("Initial verification should succeed");

    let extra_measurement = ExpectedMeasurements {
        rtmrs: Measurements {
            mrtd: [0xAA; 48],
            rtmr0: [0xBB; 48],
            rtmr1: [0xCC; 48],
            rtmr2: [0xDD; 48],
        },
        key_provider_event_digest: [0xEE; 48],
    };
    let mut superset: Vec<ExpectedMeasurements> = default_measurements().to_vec();
    superset.push(extra_measurement);

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &superset,
    );

    // then
    assert_matches!(result, Ok(()));
}
