use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// Returns the workspace root directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds a contract and returns `read` applied to the path of the compiled
/// WASM artifact.
///
/// Uses `cargo near build non-reproducible-wasm` under the hood. The caller
/// is responsible for setting all fields in `opts` (manifest_path, out_dir,
/// profile, features, etc.). Contract builds are serialized across processes,
/// and `read` runs before the next one starts, so it can safely read any file
/// the build wrote to `out_dir`.
pub fn build_contract<T>(opts: cargo_near_build::BuildOpts, read: impl FnOnce(&Path) -> T) -> T {
    // cargo-near copies the WASM out of `target/<triple>/<profile>/`, which all
    // feature variants of a crate share, after cargo has released its build lock.
    // Since Cargo 1.100 a fresh build of another variant swaps that file in
    // milliseconds, so concurrent test processes would load each other's variants.
    let _lock = lock_contract_builds();
    let artifact = cargo_near_build::build_with_cli(opts).expect("cargo near build failed");
    read(&artifact.canonicalize().unwrap())
}

fn lock_contract_builds() -> File {
    let dir = workspace_root().join("target/near");
    std::fs::create_dir_all(&dir).expect("failed to create the contract output directory");
    let lock = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("build.lock"))
        .expect("failed to open the contract build lock file");
    lock.lock()
        .expect("failed to lock the contract build lock file");
    lock
}

/// Loads the WASM from `env_var` if set, else the workspace-relative `prebuilt`
/// artifact, else a fresh build. The builder must output to `prebuilt`'s directory,
/// or every process misses the fallback's artifact and rebuilds.
pub fn must_load_wasm(env_var: &str, prebuilt: &str, builder: ContractBuilder) -> Vec<u8> {
    let prebuilt = workspace_root().join(prebuilt);
    let wasm_path = match std::env::var(env_var) {
        Ok(path) => PathBuf::from(path),
        Err(_) if prebuilt.exists() => prebuilt,
        Err(_) => {
            eprintln!("{env_var} not set and no pre-built WASM found; building from source");
            return builder.build();
        }
    };
    std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("failed to read the WASM at {}: {e}", wasm_path.display()))
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
    env: Vec<(String, String)>,
    no_default_features: bool,
}

impl ContractBuilder {
    /// Create a new builder with `manifest_path` relative to workspace root.
    pub fn new(manifest_path: &str) -> Self {
        Self {
            manifest_path: manifest_path.to_string(),
            out_dir: None,
            features: Vec::new(),
            env: Vec::new(),
            no_default_features: false,
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

    /// Set an environment variable for the contract build.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// Build without the crate's default features.
    pub fn no_default_features(mut self) -> Self {
        self.no_default_features = true;
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
            env: self.env,
            no_default_features: self.no_default_features,
            ..Default::default()
        };

        build_contract(opts, |path| {
            std::fs::read(path).unwrap_or_else(|e| {
                panic!("Failed to read contract WASM at {}: {e}", path.display())
            })
        })
    }
}
