//! Gas-budget guard for the detached `clean_expired_launcher_hashes` self-call.
//!
//! `verify_tee` spawns this `#[private]` call with a fixed `clean_expired_launcher_hashes_tera_gas`
//! budget (default 5 TGas). This test measures its actual cost on a small launcher allowlist and
//! asserts it stays under that budget, so a future change that bloats the method can't silently
//! exceed the attached gas. The cost is dominated by contract state load/store + the base
//! function-call charge, not the launcher count, so it stays flat as the allowlist changes.

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{consts::ALL_PROTOCOLS, mpc_contract::vote_add_launcher_hash},
};
use mpc_primitives::hash::LauncherImageHash;
use near_mpc_contract_interface::method_names;
use near_workspaces::types::Gas;

/// The default `clean_expired_launcher_hashes_tera_gas` the detached self-call is given.
const BUDGET_TGAS: u64 = 5;

#[tokio::test]
async fn clean_expired_launcher_hashes_within_gas_budget() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // Populate a small allowlist: two launcher hashes, each voted in by all
    // participants so they reach threshold and land in `allowed_launcher_images`.
    for byte in [1u8, 2u8] {
        let launcher_hash = LauncherImageHash::from([byte; 32]);
        for account in &mpc_signer_accounts {
            vote_add_launcher_hash(account, &contract, &launcher_hash).await?;
        }
    }

    // `clean_expired_launcher_hashes` is `#[private]`: callable only when
    // predecessor == current account. `contract.call(..)` is signed by the
    // contract's own account, so that holds.
    let execution = contract
        .call(method_names::CLEAN_EXPIRED_LAUNCHER_HASHES)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let total = execution.total_gas_burnt;
    let max_receipt = execution
        .receipt_outcomes()
        .iter()
        .map(|o| o.gas_burnt)
        .max()
        .unwrap_or(total);

    let tgas = |g: Gas| g.as_gas() as f64 / 1e12;
    eprintln!("=== clean_expired_launcher_hashes gas ===");
    eprintln!("  total_gas_burnt    = {:.3} TGas", tgas(total));
    eprintln!("  max single receipt = {:.3} TGas", tgas(max_receipt));
    eprintln!("  budget             = {BUDGET_TGAS}.000 TGas");

    let budget = Gas::from_tgas(BUDGET_TGAS);
    assert!(
        max_receipt.as_gas() < budget.as_gas(),
        "clean_expired_launcher_hashes burned {:.3} TGas, at/over its {BUDGET_TGAS} TGas budget — \
         raise clean_expired_launcher_hashes_tera_gas or shrink the method",
        tgas(max_receipt),
    );

    Ok(())
}
