use std::sync::OnceLock;
use test_utils::contract_build::ContractBuilder;

const MPC_CONTRACT_MANIFEST: &str = "crates/contract/Cargo.toml";
const MIGRATION_CONTRACT_MANIFEST: &str = "crates/test-migration-contract/Cargo.toml";
const PARALLEL_CONTRACT_MANIFEST: &str = "crates/test-parallel-contract/Cargo.toml";
const TEE_VERIFIER_MANIFEST: &str = "crates/tee-verifier/Cargo.toml";
const MPC_CONTRACT_OUT_DIR: &str = "target/near/contract-noabi";
const MPC_CONTRACT_BENCH_OUT_DIR: &str = "target/near/contract-noabi-bench";
const MPC_CONTRACT_SANDBOX_OUT_DIR: &str = "target/near/contract-noabi-sandbox";
const MPC_CONTRACT_ATTESTATION_OUT_DIR: &str = "target/near/contract-noabi-attestation";
const TEE_VERIFIER_SANDBOX_OUT_DIR: &str = "target/near/tee-verifier-sandbox";

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static CONTRACT_WITH_BENCH_METHODS: OnceLock<Vec<u8>> = OnceLock::new();
static CONTRACT_WITH_SANDBOX_TEST_METHODS: OnceLock<Vec<u8>> = OnceLock::new();
static CONTRACT_WITH_SANDBOX_TEST_ATTESTATION: OnceLock<Vec<u8>> = OnceLock::new();
static MIGRATION_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static PARALLEL_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static TEE_VERIFIER_CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();
static TEE_VERIFIER_CONTRACT_WITH_SANDBOX_TEST_HOOKS: OnceLock<Vec<u8>> = OnceLock::new();

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

/// Returns the current contract WASM with sandbox-only view methods enabled.
/// Use this for tests that need to assert internal contract state (e.g. fan-out queue
/// length) that isn't observable through the production API.
pub fn current_contract_with_sandbox_test_methods() -> &'static [u8] {
    CONTRACT_WITH_SANDBOX_TEST_METHODS.get_or_init(|| {
        ContractBuilder::new(MPC_CONTRACT_MANIFEST)
            .out_dir(MPC_CONTRACT_SANDBOX_OUT_DIR)
            .features(&["sandbox-test-methods"])
            .build()
    })
}

/// Returns the current contract WASM that can whitelist the fixture's launcher compose hash.
/// Use this only for tests that submit the Dstack fixture and need it to verify: that compose
/// hash is not derivable from the compiled-in template, so no vote can allow it.
pub fn current_contract_with_sandbox_test_attestation() -> &'static [u8] {
    CONTRACT_WITH_SANDBOX_TEST_ATTESTATION.get_or_init(|| {
        ContractBuilder::new(MPC_CONTRACT_MANIFEST)
            .out_dir(MPC_CONTRACT_ATTESTATION_OUT_DIR)
            .features(&["sandbox-test-attestation"])
            .build()
    })
}

pub fn migration_contract() -> &'static [u8] {
    MIGRATION_CONTRACT.get_or_init(|| ContractBuilder::new(MIGRATION_CONTRACT_MANIFEST).build())
}

pub fn parallel_contract() -> &'static [u8] {
    PARALLEL_CONTRACT.get_or_init(|| ContractBuilder::new(PARALLEL_CONTRACT_MANIFEST).build())
}

pub fn tee_verifier_contract() -> &'static [u8] {
    TEE_VERIFIER_CONTRACT.get_or_init(|| ContractBuilder::new(TEE_VERIFIER_MANIFEST).build())
}

/// Returns the tee-verifier WASM with the pinnable verification clock enabled.
/// Use this for tests that need the time-expired fixture quote to reach a
/// Verified verdict; everything else should deploy [`tee_verifier_contract`].
pub fn tee_verifier_contract_with_sandbox_test_hooks() -> &'static [u8] {
    TEE_VERIFIER_CONTRACT_WITH_SANDBOX_TEST_HOOKS.get_or_init(|| {
        ContractBuilder::new(TEE_VERIFIER_MANIFEST)
            .out_dir(TEE_VERIFIER_SANDBOX_OUT_DIR)
            .features(&["sandbox-test-hooks"])
            .build()
    })
}
