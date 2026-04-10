pub mod types;

/// Event name for MPC node image digest
pub const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

/// Event name for backup service image digest
pub const BACKUP_SERVICE_IMAGE_HASH_EVENT: &str = "backup-service-image-digest";

pub const DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL: &str =
    "https://cloud-api.phala.network/api/v1/attestations/verify";
