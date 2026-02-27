use crate::config::{Platform, Sha256Digest};
use crate::docker_cmd::DSTACK_UNIX_SOCKET;

#[derive(Debug, thiserror::Error)]
pub enum RtmrError {
    #[error("PLATFORM=TEE requires dstack unix socket at {0}")]
    MissingSocket(String),
    #[error("GetQuote failed: {0}")]
    GetQuoteFailed(#[source] anyhow::Error),
    #[error("EmitEvent failed: {0}")]
    EmitEventFailed(#[source] anyhow::Error),
    #[error("failed to decode digest hex: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("failed to create tokio runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

/// Check that the dstack unix socket exists.
pub fn verify_unix_socket(path: &str) -> Result<(), RtmrError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        match std::fs::metadata(path) {
            Ok(m) if m.file_type().is_socket() => Ok(()),
            _ => Err(RtmrError::MissingSocket(path.to_string())),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(RtmrError::MissingSocket(
            "unix sockets not supported on this platform".to_string(),
        ))
    }
}

/// Extend RTMR3 with the validated image digest. No-op for NonTee platform.
pub fn extend_rtmr3(platform: Platform, digest: &Sha256Digest) -> Result<(), RtmrError> {
    if platform == Platform::NonTee {
        tracing::info!("PLATFORM=NONTEE -> skipping RTMR3 extension step");
        return Ok(());
    }

    verify_unix_socket(DSTACK_UNIX_SOCKET)?;

    let bare_hex = digest.bare_hex();
    tracing::info!("Extending RTMR3 with validated hash: {bare_hex}");

    let rt = tokio::runtime::Runtime::new().map_err(RtmrError::Runtime)?;

    let client = dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

    // GetQuote as a health check before EmitEvent.
    // Python sends empty report_data, but the SDK requires 1-64 bytes.
    // A 1-byte dummy achieves the same health-check purpose.
    rt.block_on(client.get_quote(vec![0u8]))
        .map_err(RtmrError::GetQuoteFailed)?;

    // EmitEvent with the digest raw bytes.
    // The SDK hex-encodes the Vec<u8> internally, producing the same payload
    // as the Python launcher's JSON: {"event": "mpc-image-digest", "payload": "<hex>"}
    let digest_bytes = digest.to_bytes()?;
    rt.block_on(client.emit_event("mpc-image-digest".to_string(), digest_bytes))
        .map_err(RtmrError::EmitEventFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extend_rtmr3_nontee_skips() {
        let digest = Sha256Digest::parse(&"b".repeat(64)).unwrap();
        // Should succeed without calling dstack
        extend_rtmr3(Platform::NonTee, &digest).unwrap();
    }

    #[test]
    fn test_verify_unix_socket_missing() {
        assert!(verify_unix_socket("/nonexistent/socket.sock").is_err());
    }

    #[test]
    fn test_verify_unix_socket_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, "").unwrap();
        assert!(verify_unix_socket(path.to_str().unwrap()).is_err());
    }
}
