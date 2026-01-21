use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    process::Command,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

/// Maximum age (in seconds) before a cached WASM build is considered stale.
const BUILD_CACHE_TTL_SECONDS: u64 = 4;
const CURRENT_CONTRACT_PACKAGE_NAME: &str = "mpc-contract";
const DUMMY_MIGRATION_CONTRACT_PACKAGE_NAME: &str = "test-migration-contract";

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static MIGRATION_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

pub fn current_contract() -> &'static [u8] {
    CONTRACT.get_or_init(|| load_contract(CURRENT_CONTRACT_PACKAGE_NAME))
}

pub fn migration_contract() -> &'static [u8] {
    MIGRATION_CONTRACT.get_or_init(|| load_contract(DUMMY_MIGRATION_CONTRACT_PACKAGE_NAME))
}

/// Generic contract builder
fn load_contract(package_name: &str) -> Vec<u8> {
    let lockfile_name = format!("{package_name}.itest.build.lock");

    // Points to `/crates`
    let pkg_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // pointing to repository root directory.
    let project_dir = pkg_dir.join("../..");

    let artifact_name = format!("{package_name}.wasm").replace('-', "_");
    let wasm_path = project_dir.join(format!(
        "target/wasm32-unknown-unknown/release-contract/{artifact_name}"
    ));

    let lock_path = project_dir.join(lockfile_name);
    let mut lockfile = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("Failed to open lockfile");
    lockfile
        .lock_exclusive()
        .expect("Failed to lock build file");

    // Track whether bench-utils feature is enabled at compile time
    let bench_utils_enabled = cfg!(feature = "bench-utils");

    // check if we need to re-build
    let do_build = match lockfile.metadata().unwrap().len() {
        0 => true,
        _ => {
            let mut buf = String::new();
            lockfile.read_to_string(&mut buf).unwrap();
            match serde_json::from_str::<BuildLock>(&buf) {
                Ok(build_lock) => build_lock.expired(bench_utils_enabled),
                _ => true,
            }
        }
    };

    if do_build {
        #[allow(unused_mut)] // Mutated conditionally when bench-utils feature is enabled
        let mut args = vec![
            "build".to_string(),
            format!("--package={package_name}"),
            "--profile=release-contract".to_string(),
            "--target=wasm32-unknown-unknown".to_string(),
            "--locked".to_string(),
        ];

        // Include benchmark endpoints in WASM when bench-utils feature is enabled
        // Only apply this to mpc-contract, as test-migration-contract doesn't have this feature
        #[cfg(feature = "bench-utils")]
        if package_name == CURRENT_CONTRACT_PACKAGE_NAME {
            args.push("--features=bench-utils".to_string());
        }

        let status = Command::new("cargo")
            .args(&args)
            .current_dir(&project_dir)
            .status()
            .expect("Failed to run cargo build");

        assert!(status.success(), "cargo build failed");

        let status = Command::new("wasm-opt")
            .args([
                "--enable-bulk-memory",
                "-Oz",
                "-o",
                wasm_path.to_str().unwrap(),
                wasm_path.to_str().unwrap(),
            ])
            .current_dir(&project_dir)
            .status()
            .expect("Failed to run wasm-opt");

        assert!(status.success(), "wasm-opt failed");

        lockfile.set_len(0).unwrap();
        lockfile
            .write_all(
                serde_json::to_string(&BuildLock::new(bench_utils_enabled))
                    .unwrap()
                    .as_bytes(),
            )
            .expect("Failed to write timestamp to lockfile");
    }

    std::fs::read(wasm_path).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
struct BuildLock {
    timestamp: u64,
    /// Tracks whether the WASM was built with bench-utils feature.
    /// If this doesn't match the current compilation, we need to rebuild.
    bench_utils: bool,
}

impl BuildLock {
    fn new(bench_utils: bool) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            bench_utils,
        }
    }

    /// Checks if the build is stale:
    /// - older than [`BUILD_CACHE_TTL_SECONDS`], OR
    /// - was built with different bench-utils feature state
    fn expired(&self, current_bench_utils: bool) -> bool {
        // Feature mismatch requires rebuild
        if self.bench_utils != current_bench_utils {
            return true;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > BUILD_CACHE_TTL_SECONDS
    }
}
