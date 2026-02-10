use crate::primitives::ParticipantId;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const IMPORT_KEYSHARE_FILENAME: &str = "import_keyshare";

/// The import keyshare file format. Contains the ECDSA keygen output along with
/// metadata needed to validate compatibility with the current node and contract configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportKeyshareFile {
    /// The ECDSA keygen output (private_share + public_key).
    pub keygen_output: threshold_signatures::ecdsa::KeygenOutput,
    /// The participant identifier this share was generated for.
    /// Must match this node's ParticipantId in the current threshold parameters.
    pub participant_id: u32,
    /// The threshold value used when generating these shares.
    /// Must match the current contract threshold.
    pub threshold: u64,
}

pub fn read_import_keyshare(home_dir: &Path) -> anyhow::Result<Option<ImportKeyshareFile>> {
    let path = home_dir.join(IMPORT_KEYSHARE_FILENAME);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let import_file: ImportKeyshareFile = serde_json::from_slice(&data)?;
    Ok(Some(import_file))
}

pub fn validate_import_keyshare(
    import: &ImportKeyshareFile,
    my_participant_id: ParticipantId,
    current_threshold: u64,
) -> anyhow::Result<()> {
    if import.participant_id != my_participant_id.raw() {
        anyhow::bail!(
            "Import keyshare participant_id {} does not match this node's participant_id {}",
            import.participant_id,
            my_participant_id.raw()
        );
    }
    if import.threshold != current_threshold {
        anyhow::bail!(
            "Import keyshare threshold {} does not match current threshold {}",
            import.threshold,
            current_threshold
        );
    }
    Ok(())
}
