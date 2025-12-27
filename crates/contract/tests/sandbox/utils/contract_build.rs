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

    // check if we need to re-build
    let do_build = match lockfile.metadata().unwrap().len() {
        0 => true,
        _ => {
            let mut buf = String::new();
            lockfile.read_to_string(&mut buf).unwrap();
            match serde_json::from_str::<BuildLock>(&buf) {
                Ok(build_lock) => build_lock.expired(),
                _ => true,
            }
        }
    };

    if do_build {
        let status = Command::new("cargo")
            .args([
                "build",
                &format!("--package={package_name}"),
                "--profile=release-contract",
                "--target=wasm32-unknown-unknown",
                "--locked",
            ])
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
            .write_all(serde_json::to_string(&BuildLock::new()).unwrap().as_bytes())
            .expect("Failed to write timestamp to lockfile");
    }

    std::fs::read(wasm_path).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
struct BuildLock {
    timestamp: u64,
}

impl BuildLock {
    fn new() -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// checks if self is older than 4 seconds
    fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > 4
    }
}
