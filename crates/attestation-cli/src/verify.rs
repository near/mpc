use std::path::Path;

use anyhow::Context;
use attestation::{
    app_compose::AppCompose,
    attestation::{DstackAttestation, GetSingleEvent as _, VerificationError},
    measurements::{ExpectedMeasurements, Measurements},
    tcb_info::TcbInfo,
};
use include_measurements::include_measurements;
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use node_types::http_server::StaticWebData;
use sha2::{Digest, Sha256};

use crate::cli::VerifyArgs;

const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";
const KEY_PROVIDER_EVENT: &str = "key-provider";
const DEFAULT_EXPIRATION_DURATION_SECONDS: u64 = 60 * 60 * 24 * 7; // 7 days

/// Result of a successful verification.
#[derive(Debug)]
pub struct VerificationResult {
    pub mpc_image_hash: MpcDockerImageHash,
    pub launcher_compose_hash: LauncherDockerComposeHash,
    pub expiry_timestamp_seconds: u64,
}

pub fn run_verification(
    static_data: &StaticWebData,
    args: &VerifyArgs,
) -> Result<VerificationResult, VerificationError> {
    let attestation = static_data.tee_participant_info.as_ref().ok_or_else(|| {
        VerificationError::Custom(
            "tee_participant_info is null in the response — node has no attestation".into(),
        )
    })?;

    match attestation {
        mpc_attestation::attestation::Attestation::Dstack(dstack_attestation) => {
            verify_dstack(static_data, dstack_attestation, args)
        }
        mpc_attestation::attestation::Attestation::Mock(_) => Err(VerificationError::Custom(
            "attestation is a Mock — cannot verify mock attestations".into(),
        )),
    }
}

fn verify_dstack(
    static_data: &StaticWebData,
    dstack_attestation: &DstackAttestation,
    args: &VerifyArgs,
) -> Result<VerificationResult, VerificationError> {
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();

    verify_dstack_at_timestamp(static_data, dstack_attestation, args, current_timestamp)
}

pub fn verify_dstack_at_timestamp(
    static_data: &StaticWebData,
    dstack_attestation: &DstackAttestation,
    args: &VerifyArgs,
    timestamp_seconds: u64,
) -> Result<VerificationResult, VerificationError> {
    // 1. Extract and verify MPC image hash from event log
    let mpc_image_hash = extract_mpc_image_hash(&dstack_attestation.tcb_info)?;
    let allowed_image_hashes = parse_allowed_image_hashes(&args.allowed_image_hashes)?;
    verify_hash_in_list("MPC image", &mpc_image_hash, &allowed_image_hashes)?;

    // 2. Extract and verify launcher compose hash from app_compose
    let launcher_compose_hash = extract_launcher_compose_hash(&dstack_attestation.tcb_info)?;
    let allowed_compose_hashes = compute_allowed_compose_hashes(&args.launcher_compose_file)
        .map_err(|e| {
            VerificationError::Custom(format!("failed to read launcher compose file: {e}"))
        })?;
    verify_hash_in_list(
        "launcher compose",
        &launcher_compose_hash,
        &allowed_compose_hashes,
    )?;

    // 3. Build expected report data from the node's public keys
    let tls_key_bytes = static_data.near_p2p_public_key.to_bytes();
    let account_key_bytes = static_data.near_signer_public_key.to_bytes();
    let report_data =
        mpc_attestation::report_data::ReportDataV1::new(tls_key_bytes, account_key_bytes);
    let report_data: mpc_attestation::report_data::ReportData = report_data.into();

    // 4. Load measurements (custom file or compiled-in defaults)
    let measurements = load_measurements(&args.expected_measurements).map_err(|e| {
        VerificationError::Custom(format!("failed to load expected measurements: {e}"))
    })?;

    // 5. Run core DCAP verification
    dstack_attestation.verify(report_data.into(), timestamp_seconds, &measurements)?;

    let expiry_timestamp_seconds = timestamp_seconds + DEFAULT_EXPIRATION_DURATION_SECONDS;

    Ok(VerificationResult {
        mpc_image_hash,
        launcher_compose_hash,
        expiry_timestamp_seconds,
    })
}

fn extract_mpc_image_hash(tcb_info: &TcbInfo) -> Result<MpcDockerImageHash, VerificationError> {
    let event_payload = &tcb_info
        .get_single_event(MPC_IMAGE_HASH_EVENT)?
        .event_payload;

    let hash_bytes: Vec<u8> = hex::decode(event_payload).map_err(|err| {
        VerificationError::Custom(format!("MPC image hash is not valid hex: {err}"))
    })?;

    let hash_bytes: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| VerificationError::Custom("MPC image hash is not 32 bytes".into()))?;

    Ok(MpcDockerImageHash::from(hash_bytes))
}

fn extract_launcher_compose_hash(
    tcb_info: &TcbInfo,
) -> Result<LauncherDockerComposeHash, VerificationError> {
    let app_compose: AppCompose = serde_json::from_str(&tcb_info.app_compose)
        .map_err(|e| VerificationError::AppComposeParsing(e.to_string()))?;

    let hash_bytes: [u8; 32] = Sha256::digest(app_compose.docker_compose_file.as_bytes()).into();
    Ok(LauncherDockerComposeHash::from(hash_bytes))
}

fn parse_allowed_image_hashes(
    hex_strings: &[String],
) -> Result<Vec<MpcDockerImageHash>, VerificationError> {
    hex_strings
        .iter()
        .map(|s| {
            s.parse::<MpcDockerImageHash>().map_err(|e| {
                VerificationError::Custom(format!("invalid --allowed-image-hash '{s}': {e}"))
            })
        })
        .collect()
}

fn compute_allowed_compose_hashes(
    launcher_compose_path: &Path,
) -> anyhow::Result<Vec<LauncherDockerComposeHash>> {
    let contents = std::fs::read_to_string(launcher_compose_path)
        .with_context(|| format!("reading {}", launcher_compose_path.display()))?;

    let hash_bytes: [u8; 32] = Sha256::digest(contents.as_bytes()).into();
    Ok(vec![LauncherDockerComposeHash::from(hash_bytes)])
}

fn verify_hash_in_list<T: PartialEq + AsRef<[u8; 32]>>(
    name: &str,
    hash: &T,
    allowed: &[T],
) -> Result<(), VerificationError> {
    if allowed.is_empty() {
        return Err(VerificationError::Custom(format!(
            "the allowed {name} hashes list is empty"
        )));
    }
    if !allowed.contains(hash) {
        return Err(VerificationError::Custom(format!(
            "{name} hash {} is not in the allowed list",
            hex::encode(hash.as_ref())
        )));
    }
    Ok(())
}

fn load_measurements(
    path: &Option<std::path::PathBuf>,
) -> anyhow::Result<Vec<ExpectedMeasurements>> {
    match path {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let measurements = parse_measurements_from_json(&contents)
                .context("parsing expected measurements JSON")?;
            Ok(vec![measurements])
        }
        None => Ok(default_measurements()),
    }
}

fn default_measurements() -> Vec<ExpectedMeasurements> {
    vec![
        include_measurements!("../mpc-attestation/assets/tcb_info.json"),
        include_measurements!("../mpc-attestation/assets/tcb_info_dev.json"),
    ]
}

/// Parse a `TcbInfo`-format JSON into `ExpectedMeasurements`, replicating
/// the same logic as the `include_measurements!()` proc macro at runtime.
fn parse_measurements_from_json(json: &str) -> anyhow::Result<ExpectedMeasurements> {
    let tcb_info: TcbInfo = serde_json::from_str(json).context("invalid TcbInfo JSON")?;

    let rtmrs = Measurements {
        mrtd: *tcb_info.mrtd,
        rtmr0: *tcb_info.rtmr0,
        rtmr1: *tcb_info.rtmr1,
        rtmr2: *tcb_info.rtmr2,
    };

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
    use test_utils::attestation::{TEST_MPC_IMAGE_DIGEST_HEX, TEST_TCB_INFO_STRING};

    fn test_tcb_info() -> TcbInfo {
        serde_json::from_str(TEST_TCB_INFO_STRING).unwrap()
    }

    #[test]
    fn parse_allowed_image_hashes_valid_hex() {
        let hashes =
            vec!["6e5b08f91752fd7cb10349de45f74272f340fe42a172d2cbc237f3f1d5527a45".to_string()];
        let result = parse_allowed_image_hashes(&hashes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn parse_allowed_image_hashes_multiple() {
        let hashes = vec![
            "6e5b08f91752fd7cb10349de45f74272f340fe42a172d2cbc237f3f1d5527a45".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ];
        let result = parse_allowed_image_hashes(&hashes).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_allowed_image_hashes_invalid_hex() {
        let hashes = vec!["not_valid_hex".to_string()];
        parse_allowed_image_hashes(&hashes).unwrap_err();
    }

    #[test]
    fn parse_allowed_image_hashes_wrong_length() {
        let hashes = vec!["abcd".to_string()];
        parse_allowed_image_hashes(&hashes).unwrap_err();
    }

    #[test]
    fn verify_hash_in_list_match() {
        let hash = MpcDockerImageHash::from([1u8; 32]);
        let allowed = vec![MpcDockerImageHash::from([1u8; 32])];
        verify_hash_in_list("test", &hash, &allowed).unwrap();
    }

    #[test]
    fn verify_hash_in_list_no_match() {
        let hash = MpcDockerImageHash::from([1u8; 32]);
        let allowed = vec![MpcDockerImageHash::from([2u8; 32])];
        let err = verify_hash_in_list("test", &hash, &allowed).unwrap_err();
        match err {
            VerificationError::Custom(msg) => assert!(msg.contains("not in the allowed list")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_hash_in_list_empty() {
        let hash = MpcDockerImageHash::from([1u8; 32]);
        let allowed: Vec<MpcDockerImageHash> = vec![];
        let err = verify_hash_in_list("test", &hash, &allowed).unwrap_err();
        match err {
            VerificationError::Custom(msg) => assert!(msg.contains("list is empty")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn verify_hash_in_list_multiple_with_match() {
        let hash = MpcDockerImageHash::from([2u8; 32]);
        let allowed = vec![
            MpcDockerImageHash::from([1u8; 32]),
            MpcDockerImageHash::from([2u8; 32]),
            MpcDockerImageHash::from([3u8; 32]),
        ];
        verify_hash_in_list("test", &hash, &allowed).unwrap();
    }

    #[test]
    fn extract_mpc_image_hash_from_test_tcb_info() {
        let tcb_info = test_tcb_info();
        let hash = extract_mpc_image_hash(&tcb_info).unwrap();
        let expected: MpcDockerImageHash = TEST_MPC_IMAGE_DIGEST_HEX.parse().unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn extract_launcher_compose_hash_from_test_tcb_info() {
        let tcb_info = test_tcb_info();
        let hash = extract_launcher_compose_hash(&tcb_info).unwrap();
        // The hash should be a valid 32-byte SHA256 digest
        assert_ne!(*hash.as_ref(), [0u8; 32]);
    }

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
    fn parse_measurements_from_json_matches_include_macro() {
        // Use the same file that include_measurements! reads at compile time
        let json = include_str!("../../mpc-attestation/assets/tcb_info.json");
        let runtime = parse_measurements_from_json(json).unwrap();
        let compiled = include_measurements!("../mpc-attestation/assets/tcb_info.json");

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
    fn default_measurements_not_empty() {
        let m = default_measurements();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn compute_allowed_compose_hashes_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compose.yaml");
        std::fs::write(&path, "test content").unwrap();

        let hashes = compute_allowed_compose_hashes(&path).unwrap();
        assert_eq!(hashes.len(), 1);

        let expected: [u8; 32] = Sha256::digest(b"test content").into();
        assert_eq!(*hashes[0].as_ref(), expected);
    }

    #[test]
    fn compute_allowed_compose_hashes_missing_file() {
        compute_allowed_compose_hashes(std::path::Path::new("/nonexistent/file.yaml")).unwrap_err();
    }
}
