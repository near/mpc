use std::sync::OnceLock;

const MPC_CONTRACT_MANIFEST: &str = "crates/contract/Cargo.toml";
const MIGRATION_CONTRACT_MANIFEST: &str = "crates/test-migration-contract/Cargo.toml";
const MPC_CONTRACT_OUT_DIR: &str = "target/near/contract-noabi";

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static CONTRACT_WITH_BENCH_METHODS: OnceLock<Vec<u8>> = OnceLock::new();
static MIGRATION_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

/// Returns the current contract WASM without benchmark utilities.
/// Use this for most sandbox tests.
pub fn current_contract() -> &'static [u8] {
    CONTRACT.get_or_init(|| {
        test_utils::contract_build::build_contract(
            MPC_CONTRACT_MANIFEST,
            Some(MPC_CONTRACT_OUT_DIR),
            &[],
        )
    })
}

/// Returns the current contract WASM with benchmark methods enabled.
/// Use this only for gas benchmark tests that need the `bench_*` contract methods.
pub fn current_contract_with_bench_methods() -> &'static [u8] {
    CONTRACT_WITH_BENCH_METHODS.get_or_init(|| {
        test_utils::contract_build::build_contract(
            MPC_CONTRACT_MANIFEST,
            Some(MPC_CONTRACT_OUT_DIR),
            &["bench-contract-methods"],
        )
    })
}

pub fn migration_contract() -> &'static [u8] {
    MIGRATION_CONTRACT.get_or_init(|| {
        test_utils::contract_build::build_contract(MIGRATION_CONTRACT_MANIFEST, None, &[])
    })
}
