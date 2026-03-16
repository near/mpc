use ed25519_dalek::{SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_CONTRACT_ACCOUNT: &str = "test-contract.near";

#[derive(Clone)]
pub struct Contract {
    pub account_id: near_account_id::AccountId,
    pub signing_key: SigningKey,
}

impl Contract {
    pub fn public_key_str(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        let verifying_key_vec: Vec<u8> = verifying_key.as_bytes().to_vec();
        let near_pk: near_sdk::PublicKey =
            near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, verifying_key_vec)
                .unwrap();
        String::from(&near_pk)
    }
}

pub(super) fn test_contract() -> Contract {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    Contract {
        account_id: TEST_CONTRACT_ACCOUNT.parse().unwrap(),
        signing_key,
    }
}

/// Maximum age (in seconds) before a cached WASM build is considered stale.
const BUILD_CACHE_TTL_SECONDS: u64 = 4;

/// Builds `chain-gateway-test-contract` to WASM.
///
/// Uses a cross-process file lock to prevent concurrent builds from racing
/// (nextest runs each test in a separate process). Per-process caching via
/// `OnceLock` avoids redundant filesystem reads within a single process.
///
/// Runs `wasm-opt` after building to strip custom sections (ABI metadata from near-sdk)
/// that cause `PrepareError(Deserialization)` in the nearcore runtime.
pub(super) fn compiled_test_contract_wasm() -> &'static [u8] {
    static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        let project_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        let wasm_path = project_dir.join(
            "target/wasm32-unknown-unknown/release-contract/chain_gateway_test_contract.wasm",
        );

        let lock_path = project_dir.join("chain-gateway-test-contract.itest.build.lock");
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
                    "--package=chain-gateway-test-contract",
                    "--profile=release-contract",
                    "--target=wasm32-unknown-unknown",
                    "--locked",
                ])
                .current_dir(&project_dir)
                .status()
                .expect("Failed to run cargo build for test contract");

            assert!(status.success(), "cargo build for test contract failed");

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

        std::fs::read(wasm_path).expect("read compiled test contract WASM")
    })
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

    fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > BUILD_CACHE_TTL_SECONDS
    }
}
