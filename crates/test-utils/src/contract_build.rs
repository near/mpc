use std::path::{Path, PathBuf};

/// Returns the workspace root directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds a contract and returns the path to the compiled WASM artifact.
///
/// Uses `cargo near build non-reproducible-wasm` under the hood.
///
/// * `manifest_path` - Contract's `Cargo.toml`, relative to workspace root.
/// * `out_dir` - Output directory relative to workspace root. Defaults to
///   `target/near/<crate-dir>/`. Use distinct values when the same crate is
///   built with different options in parallel (e.g. with/without ABI).
/// * `opts` - Build options forwarded to `cargo-near-build`.
pub fn build_contract_path(
    manifest_path: impl AsRef<Path>,
    out_dir: Option<&str>,
    opts: cargo_near_build::BuildOpts,
) -> PathBuf {
    let abs_manifest = workspace_root().join(manifest_path.as_ref());

    let out_dir = out_dir.map(String::from).unwrap_or_else(|| {
        let dir = abs_manifest
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .expect("manifest_path must be inside a named directory");
        format!("target/near/{dir}")
    });

    let to_utf8 = |p: PathBuf| {
        cargo_near_build::camino::Utf8PathBuf::from_path_buf(p).expect("path must be valid UTF-8")
    };

    let opts = cargo_near_build::BuildOpts {
        manifest_path: Some(to_utf8(abs_manifest)),
        out_dir: Some(to_utf8(workspace_root().join(out_dir))),
        ..opts
    };

    let artifact = cargo_near_build::build_with_cli(opts).expect("cargo near build failed");
    artifact.canonicalize().unwrap()
}

/// Builds a contract WASM and returns its bytes.
///
/// Disables ABI generation and uses the `release-contract` profile.
pub fn build_contract(
    manifest_path: impl AsRef<Path>,
    out_dir: Option<&str>,
    features: &[&str],
) -> Vec<u8> {
    let opts = cargo_near_build::BuildOpts {
        profile: Some("release-contract".to_string()),
        no_abi: true,
        no_embed_abi: true,
        features: if features.is_empty() {
            None
        } else {
            Some(features.join(","))
        },
        ..Default::default()
    };

    let path = build_contract_path(manifest_path, out_dir, opts);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("Failed to read contract WASM at {}: {e}", path.display()))
}
