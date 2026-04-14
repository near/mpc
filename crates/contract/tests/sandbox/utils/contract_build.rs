use std::sync::OnceLock;
use test_utils::contract_build::ContractBuilder;

const MPC_CONTRACT_MANIFEST: &str = "crates/contract/Cargo.toml";
const MIGRATION_CONTRACT_MANIFEST: &str = "crates/test-migration-contract/Cargo.toml";
const LARGE_CONTRACT_MANIFEST: &str = "crates/test-large-contract/Cargo.toml";
const MPC_CONTRACT_OUT_DIR: &str = "target/near/contract-noabi";
const MPC_CONTRACT_BENCH_OUT_DIR: &str = "target/near/contract-noabi-bench";

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static CONTRACT_WITH_BENCH_METHODS: OnceLock<Vec<u8>> = OnceLock::new();
static MIGRATION_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static LARGE_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

/// Returns the current contract WASM without benchmark utilities.
/// Use this for most sandbox tests.
pub fn current_contract() -> &'static [u8] {
    CONTRACT.get_or_init(|| {
        ContractBuilder::new(MPC_CONTRACT_MANIFEST)
            .out_dir(MPC_CONTRACT_OUT_DIR)
            .build()
    })
}

/// Returns the current contract WASM with benchmark methods enabled.
/// Use this only for gas benchmark tests that need the `bench_*` contract methods.
pub fn current_contract_with_bench_methods() -> &'static [u8] {
    CONTRACT_WITH_BENCH_METHODS.get_or_init(|| {
        ContractBuilder::new(MPC_CONTRACT_MANIFEST)
            .out_dir(MPC_CONTRACT_BENCH_OUT_DIR)
            .features(&["bench-contract-methods"])
            .build()
    })
}

pub fn migration_contract() -> &'static [u8] {
    MIGRATION_CONTRACT.get_or_init(|| ContractBuilder::new(MIGRATION_CONTRACT_MANIFEST).build())
}

/// Returns a large (~5 MiB) contract WASM for testing chunked uploads.
pub fn large_contract() -> &'static [u8] {
    LARGE_CONTRACT.get_or_init(|| ContractBuilder::new(LARGE_CONTRACT_MANIFEST).build())
}
