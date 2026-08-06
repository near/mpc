#![allow(non_snake_case)]
//! Gas accounting for [`clean_invalid_attestations`], the reshare-time attestation sweep.
//!
//! Everything here measures the gas burnt by the sweep's own function-call receipt — the
//! quantity `clean_invalid_attestations_tera_gas` must cover. The scheduled promise pays the
//! function-call action cost and the WASM execution, but not the transaction-conversion
//! overhead that `total_gas_burnt` includes, so the receipt outcome is the comparable figure.
//!
//! [`clean_invalid_attestations__budget_covers_max_scan`] is the guard that runs in CI. The
//! remaining tests are `#[ignore]`d measurement tools that report a cost model rather than
//! asserting anything; run them explicitly when re-deriving the budget:
//!
//! ```sh
//! cargo test -p mpc-contract clean_invalid_attestations_gas -- --ignored --nocapture
//! ```

use crate::sandbox::{
    common::{candidates, init_contract_running, make_threshold_params},
    utils::{contract_build::current_contract_with_bench_methods, shared_key_utils::new_secp256k1},
};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::{
    method_names,
    types::{DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold},
};
use near_workspaces::{Account, Contract};
use serde_json::json;

/// Participants seeded by `init_running`; each gets a `Mock(Valid)` attestation that
/// survives the sweep, so they form part of the fixed cost.
const N_PARTICIPANTS: usize = 10;
/// Entries seeded per transaction, kept low enough to stay under the 300 TGas tx limit.
const SEED_CHUNK: u32 = 20;
/// Entry counts to measure. The slope across these is the marginal cost per entry.
const MEASURED_COUNTS: [u32; 4] = [0, 20, 40, 80];
/// The budget that shipped before #4035 raised it. Retained by the measurement tools to
/// characterise how the sweep behaves when its budget cannot cover the scan limit.
const PRE_FIX_BUDGET_TGAS: u64 = 10;
/// The production scan limit under test: `RESHARE_CLEAN_INVALID_ATTESTATIONS_MAX_SCAN`.
const RESHARE_MAX_SCAN: u32 = 30;
/// Removals the budget is sized to cover within a full scan. The worst case — every scanned
/// entry removable — is deliberately not funded; see `DEFAULT_CLEAN_INVALID_ATTESTATIONS_TERA_GAS`.
const REMOVALS_COVERED: u32 = 8;
/// Sandbox understates production: a `v1.signer-prod.testnet` sweep of 33 entries with 5
/// removed burned 13.121 TGas where this harness predicts 9.71. Real deployments carry more
/// participants, larger `Dstack` attestations and fuller allowlists, all of which the
/// per-entry re-verification pays for. Guards scale by this factor so a sandbox pass implies
/// a production pass.
const PRODUCTION_CALIBRATION: f64 = 1.35;
/// NEAR's per-receipt prepaid gas ceiling — the most any external caller can attach.
const MAX_PREPAID_TGAS: f64 = 300.0;

/// Guard: `clean_invalid_attestations_tera_gas` must fund a full
/// `RESHARE_CLEAN_INVALID_ATTESTATIONS_MAX_SCAN` scan plus [`REMOVALS_COVERED`] removals.
///
/// Scanning costs gas whether or not an entry is removed, so the budget and the scan limit
/// have to be sized together; this pins them so they cannot drift apart again (#4035). The
/// reshare-time promise is `.detach()`ed, so exceeding the budget does not degrade
/// gracefully — the receipt fails, every removal rolls back, and nothing propagates to the
/// `vote_reshared` transaction that scheduled it.
///
/// Measured cost is scaled by [`PRODUCTION_CALIBRATION`] before comparison, so a pass here
/// implies a pass on a real deployment rather than only in the sandbox.
///
/// The all-removable worst case is deliberately outside the funded envelope; the test reports
/// what it would cost so the gap stays visible.
#[tokio::test]
async fn clean_invalid_attestations__budget_covers_max_scan() {
    // given: a map holding exactly `RESHARE_MAX_SCAN` entries, `REMOVALS_COVERED` of them
    // removable. The participant entries count toward the scan limit — they are inserted
    // first and survive re-verification — so the seeded count is the remainder.
    let (contract, caller) = setup().await;
    let seeded = RESHARE_MAX_SCAN - N_PARTICIPANTS as u32;
    let seeded_kept = seeded - REMOVALS_COVERED;
    seed_attestations(&contract, seeded_kept, false).await;
    seed_expired_at_offset(&contract, seeded_kept, REMOVALS_COVERED).await;
    let budget_tgas = configured_budget_tgas(&contract).await;

    // when: the sweep runs with exactly the scan limit and gas the reshare promise uses.
    let burnt = try_sweep_receipt_tgas(&contract, &caller, RESHARE_MAX_SCAN, budget_tgas as f64)
        .await
        .unwrap_or_else(|| {
            panic!(
                "clean_invalid_attestations_tera_gas ({budget_tgas} TGas) cannot fund a \
                 max_scan={RESHARE_MAX_SCAN} scan with {REMOVALS_COVERED} removals even in the \
                 sandbox: the promise exhausted its budget and every removal rolled back."
            )
        });

    // then: it completes within budget once scaled to production cost.
    let projected = burnt * PRODUCTION_CALIBRATION;
    assert!(
        projected <= budget_tgas as f64,
        "max_scan={RESHARE_MAX_SCAN} with {REMOVALS_COVERED} removals burns {burnt:.1} TGas in \
         the sandbox, projecting to {projected:.1} TGas in production against a \
         {budget_tgas} TGas budget. Raise clean_invalid_attestations_tera_gas or lower \
         RESHARE_CLEAN_INVALID_ATTESTATIONS_MAX_SCAN."
    );
    assert_eq!(
        stored_attestation_count(&contract).await,
        (RESHARE_MAX_SCAN - REMOVALS_COVERED) as usize,
        "sweep should remove exactly the {REMOVALS_COVERED} expired entries"
    );

    println!(
        "  max_scan={RESHARE_MAX_SCAN}, {REMOVALS_COVERED} removed: {burnt:.1} TGas sandbox -> \
         {projected:.1} TGas projected, of {budget_tgas} TGas budgeted"
    );
}

/// Reports what the unfunded worst case — every scanned entry removable — would cost, so the
/// gap the budget deliberately leaves open stays measured rather than assumed.
#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn clean_invalid_attestations__cost_of_the_unfunded_worst_case() {
    // Every entry in the scan window that *can* be removed, is. The participant entries always
    // survive re-verification, so this is the worst case a real deployment can reach.
    let (contract, caller) = setup().await;
    let removable = RESHARE_MAX_SCAN - N_PARTICIPANTS as u32;
    seed_attestations(&contract, removable, true).await;
    let budget_tgas = configured_budget_tgas(&contract).await;

    match try_sweep_receipt_tgas(&contract, &caller, RESHARE_MAX_SCAN, MAX_PREPAID_TGAS).await {
        Some(burnt) => println!(
            "  max_scan={RESHARE_MAX_SCAN}, {removable} removed (all non-participants): \
             {burnt:.1} TGas sandbox -> {:.1} TGas projected, vs {budget_tgas} TGas budgeted",
            burnt * PRODUCTION_CALIBRATION
        ),
        None => println!("  worst case exceeded even {MAX_PREPAID_TGAS:.0} TGas"),
    }
}

/// Reads `clean_invalid_attestations_tera_gas` off the deployed contract so the guard tracks
/// `Config::default()` instead of duplicating it.
async fn configured_budget_tgas(contract: &Contract) -> u64 {
    let config: serde_json::Value = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    config["clean_invalid_attestations_tera_gas"]
        .as_u64()
        .expect("config exposes clean_invalid_attestations_tera_gas")
}

#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn clean_invalid_attestations__gas_cost_per_scanned_and_removed_entry() {
    let mut removed: Vec<(u32, f64)> = Vec::new();
    let mut kept: Vec<(u32, f64)> = Vec::new();

    for count in MEASURED_COUNTS {
        for (expired, series, label) in [
            (true, &mut removed, "removed"),
            (false, &mut kept, "kept   "),
        ] {
            let (contract, caller) = setup().await;
            seed_attestations(&contract, count, expired).await;
            let gas = sweep_receipt_tgas(&contract, &caller, RESHARE_MAX_SCAN.max(count)).await;
            println!("  {count:>3} entries {label} -> {gas:.3} TGas");
            series.push((count, gas));
        }
    }

    let (base, per_removed) = linear_fit(&removed);
    let (_, per_kept) = linear_fit(&kept);
    let affordable = ((PRE_FIX_BUDGET_TGAS as f64 - base) / per_removed)
        .floor()
        .max(0.0);

    println!("\n  fixed cost ({N_PARTICIPANTS} participant entries scanned): {base:.3} TGas");
    println!("  marginal cost per scanned+removed entry:        {per_removed:.3} TGas");
    println!("  marginal cost per scanned+kept entry:           {per_kept:.3} TGas");
    println!(
        "  cost of a full max_scan={RESHARE_MAX_SCAN} sweep, all removed: {:.1} TGas",
        base + per_removed * RESHARE_MAX_SCAN as f64
    );
    println!(
        "  cost of a full max_scan={RESHARE_MAX_SCAN} sweep, none removed: {:.1} TGas",
        base + per_kept * RESHARE_MAX_SCAN as f64
    );
    println!("  removals affordable within {PRE_FIX_BUDGET_TGAS} TGas:            {affordable:.0}");
}

/// Reproduces the `stored_attestations` shapes observed on the deployed contracts —
/// 14 entries on `v1.signer` (mainnet) and 33 on `v1.signer-prod.testnet`, measured
/// 2026-08-04 via `get_tee_accounts` — and reports the sweep cost against the budget.
///
/// Both are scanned in full because `max_scan` (100) exceeds the map size, so the reshare
/// promise pays for every stored entry.
#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn clean_invalid_attestations__budget_covers_deployed_map_sizes() {
    // (total entries, of which expired). Mainnet holds one duplicate TLS key today;
    // testnet holds 20 beyond its participant set, all plausible sweep candidates.
    for (label, total, expired) in [("mainnet", 14u32, 1u32), ("testnet", 33, 10)] {
        let (contract, caller) = setup().await;
        let seeded = total - N_PARTICIPANTS as u32;
        seed_attestations(&contract, seeded - expired, false).await;
        seed_expired_at_offset(&contract, seeded - expired, expired).await;

        let gas = sweep_receipt_tgas(&contract, &caller, RESHARE_MAX_SCAN).await;
        let verdict = if gas <= PRE_FIX_BUDGET_TGAS as f64 {
            "within budget"
        } else {
            "EXCEEDS BUDGET"
        };
        println!(
            "  {label}-shaped map ({total} entries, {expired} expired): \
             {gas:.3} TGas vs {PRE_FIX_BUDGET_TGAS} TGas budget -> {verdict}"
        );
    }
}

/// How far a permissionless external call gets when it attaches the maximum 300 TGas.
///
/// `clean_invalid_attestations` is neither `#[private]` nor signer-gated, so any account —
/// including another contract — can invoke it with its own `max_scan` and its own gas. This
/// establishes the size of backlog a single manual call can actually drain.
#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn clean_invalid_attestations__max_removals_within_max_prepaid_gas() {
    for backlog in [400u32, 700, 800] {
        let (contract, caller) = setup().await;
        seed_attestations(&contract, backlog, true).await;

        match try_sweep_receipt_tgas(
            &contract,
            &caller,
            backlog + RESHARE_MAX_SCAN,
            MAX_PREPAID_TGAS,
        )
        .await
        {
            Some(gas) => println!(
                "  {backlog} expired entries: swept in one call, {gas:.1} TGas of \
                 {MAX_PREPAID_TGAS:.0} TGas ({:.1} TGas headroom)",
                MAX_PREPAID_TGAS - gas
            ),
            None => println!(
                "  {backlog} expired entries: FAILED — exhausts the \
                 {MAX_PREPAID_TGAS:.0} TGas ceiling, all removals rolled back"
            ),
        }
    }
}

/// Records exactly what an operator can observe when the reshare-time sweep exhausts its
/// budget: the receipt status, the logs it leaves behind, and whether any entry was actually
/// reclaimed.
#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn clean_invalid_attestations__observable_effects_when_budget_exhausted() {
    // Enough entries that a 10 TGas sweep cannot finish, per the measured 0.362 TGas/removal.
    const BACKLOG: u32 = 60;

    let (contract, caller) = setup().await;
    seed_attestations(&contract, BACKLOG, true).await;
    let before = stored_attestation_count(&contract).await;

    let result = caller
        .call(contract.id(), method_names::CLEAN_INVALID_ATTESTATIONS)
        .args_json(json!({ "max_scan": RESHARE_MAX_SCAN }))
        .gas(near_workspaces::types::Gas::from_tgas(PRE_FIX_BUDGET_TGAS))
        .transact()
        .await
        .unwrap();

    let after = stored_attestation_count(&contract).await;

    println!("  entries before: {before}, after: {after}");
    println!("  succeeded: {}", result.is_success());
    println!("  outcome logs: {:?}", result.logs());
    println!(
        "  gas burnt (whole tx): {} TGas",
        result.total_gas_burnt.as_tgas()
    );
    for failure in result.failures() {
        println!(
            "  failure: {:?}",
            failure.clone().into_result().unwrap_err()
        );
    }
}

async fn stored_attestation_count(contract: &Contract) -> usize {
    let accounts: Vec<serde_json::Value> = contract
        .view(method_names::GET_TEE_ACCOUNTS)
        .await
        .unwrap()
        .json()
        .unwrap();
    accounts.len()
}

/// Gas burnt by the `clean_invalid_attestations` function-call receipt alone.
///
/// The reshare-time invocation is a scheduled promise, so it pays the function-call action
/// cost and the WASM execution but not the transaction-conversion overhead that
/// `total_gas_burnt` includes. Reading the receipt outcome isolates the comparable figure.
async fn sweep_receipt_tgas(contract: &Contract, caller: &Account, max_scan: u32) -> f64 {
    try_sweep_receipt_tgas(contract, caller, max_scan, MAX_PREPAID_TGAS)
        .await
        .expect("sweep should fit within the prepaid gas ceiling")
}

/// Returns `None` when the sweep fails — which, for a gas ceiling, means every removal in
/// the receipt was rolled back.
///
/// `near-workspaces`' `max_gas()` attaches 1000 TGas, above NEAR's 300 TGas prepaid ceiling,
/// so the budget is set explicitly rather than relying on that helper.
async fn try_sweep_receipt_tgas(
    contract: &Contract,
    caller: &Account,
    max_scan: u32,
    prepaid_tgas: f64,
) -> Option<f64> {
    let result = caller
        .call(contract.id(), method_names::CLEAN_INVALID_ATTESTATIONS)
        .args_json(json!({ "max_scan": max_scan }))
        .gas(near_workspaces::types::Gas::from_tgas(prepaid_tgas as u64))
        .transact()
        .await
        .unwrap();
    if !result.is_success() {
        return None;
    }

    let receipt = result
        .receipt_outcomes()
        .first()
        .expect("function call produces at least one receipt");
    Some(receipt.gas_burnt.as_gas() as f64 / 1e12)
}

async fn seed_attestations(contract: &Contract, count: u32, expired: bool) {
    seed_expired_at_offset_inner(contract, 0, count, expired).await
}

async fn seed_expired_at_offset(contract: &Contract, offset: u32, count: u32) {
    seed_expired_at_offset_inner(contract, offset, count, true).await
}

async fn seed_expired_at_offset_inner(contract: &Contract, start: u32, count: u32, expired: bool) {
    let mut offset = start;
    let count = start + count;
    while offset < count {
        let chunk = SEED_CHUNK.min(count - offset);
        let result = contract
            .as_account()
            .call(contract.id(), "bench_seed_attestations")
            .args_json(json!({ "offset": offset, "count": chunk, "expired": expired }))
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(
            result.is_success(),
            "seeding failed (offset {offset}): {:?}",
            result.failures()
        );
        offset += chunk;
    }
}

/// Least-squares fit of `gas = base + per_entry * removals`.
fn linear_fit(points: &[(u32, f64)]) -> (f64, f64) {
    let n = points.len() as f64;
    let sum_x: f64 = points.iter().map(|(x, _)| *x as f64).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| *y).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| *x as f64 * y).sum();
    let sum_xx: f64 = points.iter().map(|(x, _)| (*x as f64).powi(2)).sum();
    let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x * sum_x);
    let intercept = (sum_y - slope * sum_x) / n;
    (intercept, slope)
}

async fn setup() -> (Contract, Account) {
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION)
        .await
        .unwrap();
    let contract = worker
        .dev_deploy(current_contract_with_bench_methods())
        .await
        .unwrap();

    let account_ids: Vec<AccountId> = (0..N_PARTICIPANTS)
        .map(|i| format!("node-{i}.test.near").parse().unwrap())
        .collect();
    let participants = candidates(Some(account_ids));
    let threshold_params = make_threshold_params(&participants);

    let domain_id = DomainId(0);
    let domain = DomainConfig {
        id: domain_id,
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(2),
        purpose: DomainPurpose::Sign,
    };
    let (dto_pk, _) = new_secp256k1();
    let public_key: PublicKeyExtended = dto_pk.try_into().unwrap();
    let key = KeyForDomain {
        attempt: AttemptId::new(),
        domain_id,
        key: public_key,
    };
    let keyset = Keyset::new(EpochId::new(1), vec![key]);
    init_contract_running(&contract, vec![domain], 2, keyset, threshold_params, None).await;

    let caller = worker.root_account().unwrap();
    (contract, caller)
}
