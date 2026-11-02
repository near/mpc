//! Extends RTMR3 with a dstack runtime event directly through the kernel, the way
//! dstack's own boot code does (`dstack_attest::emit_runtime_event`). dstack 0.6
//! removed the guest-agent `EmitEvent` API that wrapped this.
//!
//! The resulting RTMR3 digest and event-log line are byte-identical to what the
//! 0.5.x `EmitEvent` produced, so verifiers replaying RTMR3 are unaffected.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use base64::Engine as _;
use sha2::{Digest as _, Sha384};

/// dstack's event type for runtime events (not a TCG-defined type).
const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// The only digest format our verifier replays. dstack selects it per CVM via the
/// app-compose `event_log_version`, defaulting to 1.
const SUPPORTED_EVENT_LOG_VERSION: &str = "1";

/// Container paths of the dstack runtime-event files and the RTMR3 sysfs attribute.
/// The launcher compose must bind-mount `/run/log/dstack` and the guest's
/// `/sys/devices/virtual/misc/tdx_guest/measurements` read-write at these paths.
#[derive(Debug, Clone)]
pub struct RuntimeEventPaths {
    pub event_log: PathBuf,
    pub lock: PathBuf,
    pub version: PathBuf,
    pub rtmr3: PathBuf,
}

impl Default for RuntimeEventPaths {
    fn default() -> Self {
        Self {
            event_log: "/run/log/dstack/runtime_events.log".into(),
            lock: "/run/log/dstack/runtime_event.lock".into(),
            version: "/run/log/dstack/runtime_event_version".into(),
            rtmr3: "/tdx-measurements/rtmr3:sha384".into(),
        }
    }
}

impl RuntimeEventPaths {
    /// Whether the guest exposes RTMR extension through sysfs (dstack 0.6+ kernels).
    pub fn rtmr_sysfs_available(&self) -> bool {
        self.rtmr3.exists()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RuntimeEventError {
    #[error("failed to read event log version {path}: {source}")]
    ReadVersion {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("unsupported runtime event log version {0:?}, expected {SUPPORTED_EVENT_LOG_VERSION}")]
    UnsupportedVersion(String),
    #[error("failed to lock {path}: {source}")]
    Lock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to extend RTMR3 via {path}: {source}")]
    ExtendRtmr {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to append to event log {path}: {source}")]
    AppendLog {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeEvent<'a> {
    pub name: &'a str,
    pub payload: &'a [u8],
}

impl RuntimeEvent<'_> {
    /// `SHA384(event_type_le || ":" || name || ":" || payload)` — dstack's v1 digest.
    pub fn v1_digest(&self) -> [u8; 48] {
        Sha384::new()
            .chain_update(DSTACK_RUNTIME_EVENT_TYPE.to_le_bytes())
            .chain_update(b":")
            .chain_update(self.name.as_bytes())
            .chain_update(b":")
            .chain_update(self.payload)
            .finalize()
            .into()
    }

    fn log_line(&self) -> String {
        serde_json::json!({
            "event": self.name,
            "payload": base64::engine::general_purpose::STANDARD.encode(self.payload),
        })
        .to_string()
    }

    /// Extends RTMR3 and appends the matching event-log line, holding dstack's
    /// runtime-event lock so the two cannot interleave with dstack's own events.
    /// RTMR3 is extended first: a failed extension must not leave an unmeasured
    /// line in the log.
    pub fn emit(&self, paths: &RuntimeEventPaths) -> Result<(), RuntimeEventError> {
        let version = std::fs::read_to_string(&paths.version).map_err(|source| {
            RuntimeEventError::ReadVersion {
                path: paths.version.clone(),
                source,
            }
        })?;
        if version.trim() != SUPPORTED_EVENT_LOG_VERSION {
            return Err(RuntimeEventError::UnsupportedVersion(version.trim().into()));
        }

        let _lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&paths.lock)
            .and_then(|file| file.lock().map(|()| file))
            .map_err(|source| RuntimeEventError::Lock {
                path: paths.lock.clone(),
                source,
            })?;

        OpenOptions::new()
            .write(true)
            .open(&paths.rtmr3)
            .and_then(|mut file| file.write_all(&self.v1_digest()))
            .map_err(|source| RuntimeEventError::ExtendRtmr {
                path: paths.rtmr3.clone(),
                source,
            })?;

        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&paths.event_log)
            .and_then(|mut file| writeln!(file, "{}", self.log_line()))
            .map_err(|source| RuntimeEventError::AppendLog {
                path: paths.event_log.clone(),
                source,
            })?;

        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    const IMAGE_DIGEST_HEX: &str =
        "564a5aebc33495d5610626d23cb9e3da8e9d531d0edff9e38aa1ccaf059c15d3";
    // Digest dstack 0.6.1 extended RTMR3 with for this event on a real TDX CVM.
    const EXPECTED_DIGEST_HEX: &str = "0405a5706797115cdcccb66841205179fa5c2d989ad42fee2e2fab4c5b52bb6d9aa9bf8a86755d37e8566fdaabebc468";

    fn image_digest() -> Vec<u8> {
        hex::decode(IMAGE_DIGEST_HEX).unwrap()
    }

    fn paths_in(dir: &std::path::Path, version: &str) -> RuntimeEventPaths {
        let paths = RuntimeEventPaths {
            event_log: dir.join("runtime_events.log"),
            lock: dir.join("runtime_event.lock"),
            version: dir.join("runtime_event_version"),
            rtmr3: dir.join("rtmr3"),
        };
        std::fs::write(&paths.version, version).unwrap();
        std::fs::write(&paths.rtmr3, b"").unwrap();
        paths
    }

    #[test]
    fn v1_digest__should_match_dstack_measurement() {
        // Given
        let payload = image_digest();
        let event = RuntimeEvent {
            name: "mpc-image-digest",
            payload: &payload,
        };

        // When
        let digest = event.v1_digest();

        // Then
        assert_eq!(hex::encode(digest), EXPECTED_DIGEST_HEX);
    }

    #[test]
    fn emit__should_write_digest_and_dstack_log_line() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path(), "1\n");
        let payload = image_digest();
        let event = RuntimeEvent {
            name: "mpc-image-digest",
            payload: &payload,
        };

        // When
        event.emit(&paths).unwrap();

        // Then
        assert_eq!(
            hex::encode(std::fs::read(&paths.rtmr3).unwrap()),
            EXPECTED_DIGEST_HEX
        );
        assert_eq!(
            std::fs::read_to_string(&paths.event_log).unwrap(),
            "{\"event\":\"mpc-image-digest\",\"payload\":\"Vkpa68M0ldVhBibSPLnj2o6dUx0O3/njiqHMrwWcFdM=\"}\n"
        );
    }

    #[test]
    fn emit__should_refuse_unsupported_event_log_version() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path(), "2");
        let payload = image_digest();
        let event = RuntimeEvent {
            name: "mpc-image-digest",
            payload: &payload,
        };

        // When
        let result = event.emit(&paths);

        // Then
        assert!(matches!(result, Err(RuntimeEventError::UnsupportedVersion(v)) if v == "2"));
        assert!(std::fs::read(&paths.rtmr3).unwrap().is_empty());
        assert!(!paths.event_log.exists());
    }
}
