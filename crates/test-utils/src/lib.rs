pub mod attestation;
pub mod contract_build;
pub mod contract_types;
#[cfg(feature = "sandbox")]
pub mod sandbox;

/// Version of the `near-sandbox` binary the test sandboxes run.
/// Single source of truth shared by the e2e-tests crate and the contract test crates.
/// `scripts/check-sandbox-image-version.sh` enforces that this stays in lockstep with
/// the workspace's nearcore tag.
pub const DEFAULT_SANDBOX_VERSION: &str = "2.14.0";

/// Protocol version mainnet runs. It can lag behind [`DEFAULT_SANDBOX_VERSION`]'s
/// protocol until validators vote the upgrade in.
pub const MAINNET_PROTOCOL_VERSION: u32 = 88;

/// Genesis overrides that start a sandbox at `protocol_version` instead of its
/// binary's latest protocol.
pub fn pinned_protocol_genesis(protocol_version: u32) -> serde_json::Value {
    // The sandbox validator votes for its binary's latest protocol, which takes
    // effect two epochs later. Epochs this long keep the pinned protocol for the
    // whole test.
    const EPOCH_LENGTH: u32 = 100_000;
    serde_json::json!({
        "protocol_version": protocol_version,
        "epoch_length": EPOCH_LENGTH,
    })
}
