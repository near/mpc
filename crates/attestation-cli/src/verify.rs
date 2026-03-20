use std::path::Path;

use anyhow::Context;
use attestation::{
    attestation::VerificationError,
    measurements::{ExpectedMeasurements, Measurements},
    tcb_info::TcbInfo,
};
use mpc_attestation::attestation::{ValidatedDstackAttestation, VerifiedAttestation};
use mpc_primitives::hash::{LauncherDockerComposeHash, DockerImageHash};
use node_types::http_server::StaticWebData;
use sha2::{Digest, Sha256};

use crate::cli::Cli;

const KEY_PROVIDER_EVENT: &str = "key-provider";

/// Result of a successful verification.
#[derive(Debug)]
pub struct VerificationResult {
    pub mpc_image_hash: DockerImageHash,
    pub launcher_compose_hash: LauncherDockerComposeHash,
    pub expiry_timestamp_seconds: u64,
    pub measurements: ExpectedMeasurements,
}

pub fn run_verification(
    static_data: &StaticWebData,
    cli: &Cli,
) -> Result<VerificationResult, VerificationError> {
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();

    verify_at_timestamp(static_data, cli, current_timestamp)
}

pub fn verify_at_timestamp(
    static_data: &StaticWebData,
    cli: &Cli,
    timestamp_seconds: u64,
) -> Result<VerificationResult, VerificationError> {
    let attestation = static_data.tee_participant_info.as_ref().ok_or_else(|| {
        VerificationError::Custom(
            "tee_participant_info is null in the response — node has no attestation".into(),
        )
    })?;

    // Build expected report data from the node's public keys
    let tls_key_bytes = *static_data.near_p2p_public_key.as_bytes();
    let account_key_bytes = *static_data.near_signer_public_key.as_bytes();
    let report_data =
        mpc_attestation::report_data::ReportDataV1::new(tls_key_bytes, account_key_bytes);
    let report_data: mpc_attestation::report_data::ReportData = report_data.into();

    // Compute allowed compose hash from the launcher compose file
    let allowed_compose_hash =
        compute_allowed_compose_hash(&cli.launcher_compose_file).map_err(|e| {
            VerificationError::Custom(format!("failed to read launcher compose file: {e}"))
        })?;

    // Load measurements (custom file or compiled-in defaults)
    let measurements = load_measurements(&cli.expected_measurements).map_err(|e| {
        VerificationError::Custom(format!("failed to load expected measurements: {e}"))
    })?;

    // Single verify call — same verification logic as the contract and node
    let verified = attestation.verify(
        report_data.into(),
        timestamp_seconds,
        &cli.allowed_image_hashes,
        &[allowed_compose_hash],
        &measurements,
    )?;

    // Extract results from the verified attestation
    match verified {
        VerifiedAttestation::Dstack(ValidatedDstackAttestation {
            mpc_image_hash,
            launcher_compose_hash,
            expiry_timestamp_seconds,
            measurements,
        }) => Ok(VerificationResult {
            mpc_image_hash,
            launcher_compose_hash,
            expiry_timestamp_seconds,
            measurements,
        }),
        VerifiedAttestation::Mock(_) => Err(VerificationError::Custom(
            "attestation is a Mock — cannot produce verification result".into(),
        )),
    }
}

fn compute_allowed_compose_hash(
    launcher_compose_path: &Path,
) -> anyhow::Result<LauncherDockerComposeHash> {
    let contents = std::fs::read_to_string(launcher_compose_path)
        .with_context(|| format!("reading {}", launcher_compose_path.display()))?;

    let hash_bytes: [u8; 32] = Sha256::digest(contents.as_bytes()).into();
    Ok(LauncherDockerComposeHash::from(hash_bytes))
}

fn load_measurements(
    path: &Option<std::path::PathBuf>,
) -> anyhow::Result<Vec<ExpectedMeasurements>> {
    match path {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let measurement = parse_measurements_from_json(&contents)
                .context("parsing expected measurements JSON")?;
            Ok(vec![measurement])
        }
        None => Ok(mpc_attestation::attestation::default_measurements().to_vec()),
    }
}

/// Parse a `TcbInfo`-format JSON into `ExpectedMeasurements`, replicating
/// the same logic as the `include_measurements!()` proc macro at runtime.
fn parse_measurements_from_json(json: &str) -> anyhow::Result<ExpectedMeasurements> {
    let tcb_info: TcbInfo = serde_json::from_str(json).context("invalid TcbInfo JSON")?;

    let rtmrs = Measurements::from(&tcb_info);

    let key_provider_events: Vec<_> = tcb_info
        .event_log
        .iter()
        .filter(|e| e.event == KEY_PROVIDER_EVENT)
        .collect();

    anyhow::ensure!(
        key_provider_events.len() == 1,
        "expected exactly one key-provider event, found {}",
        key_provider_events.len()
    );

    let key_provider_event_digest: [u8; 48] = *key_provider_events[0].digest;

    Ok(ExpectedMeasurements {
        rtmrs,
        key_provider_event_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::attestation::TEST_TCB_INFO_STRING;

    #[test]
    fn parse_measurements_from_json_valid() {
        let measurements = parse_measurements_from_json(TEST_TCB_INFO_STRING).unwrap();
        assert_ne!(measurements.rtmrs.mrtd, [0u8; 48]);
        assert_ne!(measurements.rtmrs.rtmr0, [0u8; 48]);
        assert_ne!(measurements.rtmrs.rtmr1, [0u8; 48]);
        assert_ne!(measurements.rtmrs.rtmr2, [0u8; 48]);
        assert_ne!(measurements.key_provider_event_digest, [0u8; 48]);
    }

    #[test]
    fn parse_measurements_from_json_matches_compiled() {
        let json = include_str!("../../mpc-attestation/assets/tcb_info.json");
        let runtime = parse_measurements_from_json(json).unwrap();
        let compiled = &mpc_attestation::attestation::default_measurements()[0];

        assert_eq!(runtime.rtmrs.mrtd, compiled.rtmrs.mrtd);
        assert_eq!(runtime.rtmrs.rtmr0, compiled.rtmrs.rtmr0);
        assert_eq!(runtime.rtmrs.rtmr1, compiled.rtmrs.rtmr1);
        assert_eq!(runtime.rtmrs.rtmr2, compiled.rtmrs.rtmr2);
        assert_eq!(
            runtime.key_provider_event_digest,
            compiled.key_provider_event_digest
        );
    }

    #[test]
    fn parse_measurements_from_json_invalid() {
        parse_measurements_from_json("not json").unwrap_err();
    }

    #[test]
    fn compute_allowed_compose_hash_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compose.yaml");
        std::fs::write(&path, "test content").unwrap();

        let hash = compute_allowed_compose_hash(&path).unwrap();

        let expected: [u8; 32] = Sha256::digest(b"test content").into();
        assert_eq!(*hash.as_ref(), expected);
    }

    #[test]
    fn compute_allowed_compose_hash_missing_file() {
        compute_allowed_compose_hash(std::path::Path::new("/nonexistent/file.yaml")).unwrap_err();
    }
}
