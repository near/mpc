pub mod attestation;
pub mod contract_build;
pub mod contract_types;

/// Sandbox binary version passed to `near_workspaces::sandbox_with_version`.
/// Single source of truth shared by the e2e-tests crate and the contract test crates.
/// `scripts/check-sandbox-image-version.sh` enforces that this stays in lockstep with
/// the workspace's nearcore tag.
pub const DEFAULT_SANDBOX_VERSION: &str = "2.11.1";
