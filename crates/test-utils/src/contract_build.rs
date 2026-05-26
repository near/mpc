use std::path::{Path, PathBuf};

/// Returns the workspace root directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `CliDescription` whose command prefix passes `--skip-rust-version-check` to the
/// `cargo-near` subprocess invoked by `build_with_cli`.
// TODO(#3363): drop this helper and the `cli_description` override once
// cargo-near-build ships near/cargo-near#420, then set
// `BuildOpts::skip_rust_version_check: true` instead.
pub fn skip_rust_version_check_cli_description() -> cargo_near_build::CliDescription {
    cargo_near_build::CliDescription {
        cli_name_abi: "cargo-near".into(),
        cli_command_prefix: vec![
            "cargo".into(),
            "near".into(),
            "build".into(),
            "non-reproducible-wasm".into(),
            "--skip-rust-version-check".into(),
        ],
    }
}

/// Builds a contract and returns the path to the compiled WASM artifact.
///
/// Uses `cargo near build non-reproducible-wasm` under the hood. The caller
/// is responsible for setting all fields in `opts` (manifest_path, out_dir,
/// profile, features, etc.).
pub fn build_contract_path(opts: cargo_near_build::BuildOpts) -> PathBuf {
    let artifact = cargo_near_build::build_with_cli(opts).expect("cargo near build failed");
    artifact.canonicalize().unwrap()
}

/// Builder for compiling a NEAR contract WASM with sensible test defaults.
///
/// Disables ABI generation and uses the `release-contract` profile by default.
///
/// ```ignore
/// let wasm = ContractBuilder::new("crates/contract/Cargo.toml")
///     .out_dir("target/near/contract-noabi")
///     .features(&["bench-contract-methods"])
///     .build();
/// ```
pub struct ContractBuilder {
    manifest_path: String,
    out_dir: Option<String>,
    features: Vec<String>,
}

impl ContractBuilder {
    /// Create a new builder with `manifest_path` relative to workspace root.
    pub fn new(manifest_path: &str) -> Self {
        Self {
            manifest_path: manifest_path.to_string(),
            out_dir: None,
            features: Vec::new(),
        }
    }

    /// Set the output directory (relative to workspace root).
    ///
    /// Use distinct values when the same crate is built with different options
    /// in parallel (e.g. with/without ABI) to avoid artifact collisions.
    /// Defaults to `target/near/<crate-dir>/`.
    pub fn out_dir(mut self, out_dir: &str) -> Self {
        self.out_dir = Some(out_dir.to_string());
        self
    }

    /// Add cargo features to enable.
    pub fn features(mut self, features: &[&str]) -> Self {
        self.features = features.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Build the contract and return the WASM bytes.
    pub fn build(self) -> Vec<u8> {
        let abs_manifest = workspace_root().join(&self.manifest_path);

        let out_dir = self.out_dir.unwrap_or_else(|| {
            let dir = abs_manifest
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .expect("manifest_path must be inside a named directory");
            format!("target/near/{dir}")
        });

        let to_utf8 = |p: PathBuf| {
            cargo_near_build::camino::Utf8PathBuf::from_path_buf(p)
                .expect("path must be valid UTF-8")
        };

        let opts = cargo_near_build::BuildOpts {
            manifest_path: Some(to_utf8(abs_manifest)),
            out_dir: Some(to_utf8(workspace_root().join(out_dir))),
            profile: Some("release-contract".to_string()),
            no_abi: true,
            no_embed_abi: true,
            features: if self.features.is_empty() {
                None
            } else {
                Some(self.features.join(","))
            },
            // Bypass cargo-near's rustc >= 1.87 refusal: the historical bulk-memory
            // incompatibility with the nearcore contract VM has been resolved
            // upstream, so the check is now obsolete and would otherwise block
            // contract builds with the workspace's current toolchain.
            //
            // `BuildOpts::skip_rust_version_check` is honored only by the
            // in-process build path; `build_with_cli` invokes a separate
            // `cargo-near` process whose CLI doesn't read that field. We inject
            // `--skip-rust-version-check` into the prefix so the subprocess sees it.
            cli_description: skip_rust_version_check_cli_description(),
            ..Default::default()
        };

        let path = build_contract_path(opts);
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read contract WASM at {}: {e}", path.display()))
    }
}
