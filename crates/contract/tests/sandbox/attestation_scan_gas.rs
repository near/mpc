#![allow(non_snake_case)]

//! Sandbox benchmark sweeping the number of attacker controlled entries in
//! `stored_attestations` ahead of a participant's matchable attestation, to measure how
//! [`MpcContract::register_foreign_chains_config`] scales with it.
//!
//! While callers are resolved by scanning the map, `lookup_node_id_by_signer_pk` returns
//! the FIRST entry whose `account_public_key` matches the caller's signer key, so the
//! worst case is a flood of attacker entries stored AFTER the setup participants but
//! BEFORE the victim's attestation: the scan reads and borsh decodes every attacker
//! entry (~600 B each) before the match. This is the position of any node that onboards
//! or migrates after a flood.
//!
//! At each fill level N (median of 3 runs) it measures `total_gas_burnt` of
//! `register_foreign_chains_config` (victim caller, worst-case ordering), the same call
//! with only the conventional 300 Tgas attached, `verify_tee`,
//! `get_attestation` (point lookup), and
//! `submit_participant_info` (write path). The sweep then bisects for the smallest N that
//! exceeds the runtime gas cap (`max_total_prepaid_gas`, 1000 Tgas in the sandbox and on
//! recent mainnet protocol versions) and for the 300 Tgas attachment failure.
//!
//! Measured with the scan in place (sandbox 2.13.4): it cost ~0.18 Tgas per attacker
//! entry; the 1000 Tgas cap was hit between N=5320 and N=5562, a 300 Tgas attachment
//! between N=1500 and N=1660. `verify_tee`, `get_attestation`, and
//! `submit_participant_info` were flat in N.
//!
//! Heavy: run explicitly, e.g.
//! `nix develop -c cargo test -p mpc-contract --test test attestation_scan_gas_curve_sweep -- --ignored --nocapture`.
//! The sweep list can be overridden with `ATTESTATION_SCAN_SWEEP_NS=0,10,50,...`.

use crate::sandbox::common::{gen_accounts, init_contract_running, make_threshold_params};
use crate::sandbox::utils::contract_build::current_contract;
use crate::sandbox::utils::mpc_contract::{
    available_attestation_grants, get_config, get_participant_attestation,
    prepay_and_submit_participant_info, prepay_attestation_grants,
};
use crate::sandbox::utils::shared_key_utils::new_secp256k1;
use futures::future::join_all;
use mpc_contract::primitives::participants::{ParticipantInfo, Participants};
use near_mpc_contract_interface::{method_names, types as dtos};
use near_sdk::Gas;
use near_workspaces::network::Sandbox;
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;
use std::collections::BTreeSet;

/// Participants attested during setup; the victim is the 5th threshold participant.
const SETUP_PARTICIPANTS: usize = 4;
/// Default attacker entry counts swept; override with `ATTESTATION_SCAN_SWEEP_NS=0,10,...`.
const SWEEP_NS: &[usize] = &[0, 10, 50, 100, 250, 500, 1000, 2000, 3000, 4000, 5000];
/// Spare grants bought with the fill prepay; one is consumed by the measured submit run.
const SPARE_GRANTS: usize = 3;
/// Concurrent `submit_participant_info` fill transactions per batch.
const FILL_CONCURRENCY: usize = 50;
/// Bisection stops when the failing and passing fill levels are this close.
const BISECT_RESOLUTION: usize = 100;
/// Bisection round cap, to bound total sandbox time.
const MAX_BISECTIONS: usize = 4;
/// Attached gas for fill path transactions (prepay and submit); unburnt gas is refunded.
const FILL_TX_GAS: Gas = Gas::from_tgas(100);

/// Key family markers so fabricated TLS keys never collide across roles.
const PARTICIPANT_TLS_MARKER: u8 = 0x01;
const VICTIM_TLS_MARKER: u8 = 0x02;
const ATTACKER_TLS_MARKER: u8 = 0xAA;
const MEASURED_SUBMIT_TLS_MARKER: u8 = 0xBB;

struct OpMeasurement {
    gas_samples: Vec<u64>,
    error: Option<String>,
}

impl OpMeasurement {
    fn median_gas(&self) -> Option<u64> {
        let mut samples = self.gas_samples.clone();
        samples.sort_unstable();
        samples.get(samples.len() / 2).copied()
    }

    fn status(&self) -> String {
        match &self.error {
            None => "ok".to_string(),
            Some(err) => format!("FAILED: {err}"),
        }
    }
}

struct FillLevelMeasurement {
    n_attacker_entries: usize,
    fee_millinear: u64,
    register: OpMeasurement,
    /// `register_foreign_chains_config` with only the conventional 300 Tgas attached.
    register_300: OpMeasurement,
    verify_tee: OpMeasurement,
    point_lookup: OpMeasurement,
    submit: OpMeasurement,
}

/// Deterministic Ed25519 key distinct from every account key and other fabricated keys.
fn fabricated_tls_key(index: usize, marker: u8) -> dtos::Ed25519PublicKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[8] = marker;
    dtos::Ed25519PublicKey::from(bytes)
}

fn sweep_ns() -> Vec<usize> {
    match std::env::var("ATTESTATION_SCAN_SWEEP_NS") {
        Ok(s) => s
            .split(',')
            .filter_map(|part| part.trim().parse().ok())
            .collect(),
        Err(_) => SWEEP_NS.to_vec(),
    }
}

async fn record_run(
    account: &Account,
    contract: &Contract,
    method: &str,
    args: serde_json::Value,
    attached_gas: Option<Gas>,
) -> (u64, Option<String>) {
    let mut call = account.call(contract.id(), method).args_json(args);
    call = match attached_gas {
        Some(gas) => call.gas(gas),
        None => call.max_gas(),
    };
    let result = call
        .transact()
        .await
        .expect("transaction dispatch should not fail");
    let gas = result.total_gas_burnt.as_gas();
    let error = result.into_result().err().map(|failure| {
        let text = failure
            .failures()
            .iter()
            .map(|outcome| format!("{outcome:?}"))
            .collect::<Vec<_>>()
            .join(" | ");
        // The Debug blob starts with the whole outcome; the guest message sits in
        // ExecutionError("...") at the end. Extract it for a readable failure reason.
        text.match_indices("ExecutionError(\"")
            .next()
            .and_then(|(index, _)| {
                let start = index + "ExecutionError(\"".len();
                text[start..]
                    .find('"')
                    .map(|end| text[start..start + end].to_string())
            })
            .unwrap_or_else(|| {
                let mut truncated = text;
                truncated.truncate(300);
                truncated
            })
    });
    (gas, error)
}

async fn measure_op(
    account: &Account,
    contract: &Contract,
    method: &str,
    args: serde_json::Value,
    runs: usize,
    attached_gas: Option<Gas>,
) -> OpMeasurement {
    let mut gas_samples = Vec::with_capacity(runs);
    let mut error = None;
    for _ in 0..runs {
        let (gas, run_error) =
            record_run(account, contract, method, args.clone(), attached_gas).await;
        gas_samples.push(gas);
        if error.is_none() {
            error = run_error;
        }
    }
    OpMeasurement { gas_samples, error }
}

struct BenchEnv {
    worker: Worker<Sandbox>,
    contract: Contract,
    /// Attested first, in order (map positions 0..4).
    participants: Vec<Account>,
    /// Fifth participant; submits its attestation only AFTER the fill, so the scan walks
    /// the whole map before matching it.
    victim: Account,
    /// Caller that is not a participant and floods the map.
    attacker: Account,
    victim_tls_key: dtos::Ed25519PublicKey,
    attestation_storage_fee_millinear: u64,
}

/// Contract in Running state with 5 participants (governance threshold 3, one ForeignTx
/// domain) and the 4 setup participants attested.
async fn setup_bench_env() -> anyhow::Result<BenchEnv> {
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION).await?;
    let contract = worker.dev_deploy(current_contract()).await?;
    let (accounts, _) = gen_accounts(&worker, SETUP_PARTICIPANTS + 2).await;
    let (participants, victim, attacker) = (
        accounts[..SETUP_PARTICIPANTS].to_vec(),
        accounts[SETUP_PARTICIPANTS].clone(),
        accounts[SETUP_PARTICIPANTS + 1].clone(),
    );

    // The victim is a threshold participant, so `init_running` seeds a mock attestation
    // for it keyed by its participant info TLS key. The victim's REAL attestation is
    // submitted AFTER the fill under a DIFFERENT TLS key, so it is appended at the very
    // end of the map instead of replacing its genesis slot in place — without this, the
    // scan would match at the genesis position and never walk the attacker entries.
    let victim_tls_key = fabricated_tls_key(1, VICTIM_TLS_MARKER);

    // Each threshold participant's info TLS key matches the TLS key of the attestation it
    // will submit, so `verify_tee` finds and re-verifies all five and stays in Running.
    let mut threshold_set = Participants::new();
    for (index, account) in participants.iter().enumerate() {
        threshold_set.insert(
            account.id().clone(),
            ParticipantInfo {
                url: "127.0.0.1".to_string(),
                tls_public_key: fabricated_tls_key(index, PARTICIPANT_TLS_MARKER),
            },
        )?;
    }
    threshold_set.insert(
        victim.id().clone(),
        ParticipantInfo {
            url: "127.0.0.1".to_string(),
            tls_public_key: fabricated_tls_key(0, VICTIM_TLS_MARKER),
        },
    )?;
    let threshold_params = make_threshold_params(&threshold_set);

    let domain_id = dtos::DomainId(0);
    let domains = vec![dtos::DomainConfig {
        id: domain_id,
        protocol: dtos::Protocol::CaitSith,
        reconstruction_threshold: dtos::ReconstructionThreshold::new(3),
        purpose: dtos::DomainPurpose::ForeignTx,
    }];
    let (dto_pk, _) = new_secp256k1();
    let key = dtos::KeyForDomain {
        attempt: dtos::AttemptId::new(),
        domain_id,
        key: dto_pk.into(),
    };
    let keyset = dtos::Keyset::new(dtos::EpochId::new(1), vec![key]);
    init_contract_running(&contract, domains, 1, keyset, threshold_params, None).await;

    // Map insertion order is submission order: the 4 setup participants go first, so the
    // victim's later entry is the only one matching its signer key AND the last in the map.
    let attestation = dtos::Attestation::Mock(dtos::MockAttestation::Valid);
    for (index, account) in participants.iter().enumerate() {
        let tls_key = fabricated_tls_key(index, PARTICIPANT_TLS_MARKER);
        let result =
            prepay_and_submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        anyhow::ensure!(
            result.is_success(),
            "participant attestation submission failed: {result:?}"
        );
    }

    let config = get_config(&contract).await?;

    Ok(BenchEnv {
        worker,
        contract,
        participants,
        victim,
        attacker,
        victim_tls_key,
        attestation_storage_fee_millinear: config.attestation_storage_fee_millinear,
    })
}

impl BenchEnv {
    fn fee_token(&self, grants: u128) -> NearToken {
        NearToken::from_millinear(u128::from(self.attestation_storage_fee_millinear) * grants)
    }

    fn yocto(&self, token: NearToken) -> u128 {
        token.as_yoctonear()
    }

    async fn submit_attacker_entry(&self, index: usize, marker: u8) -> anyhow::Result<bool> {
        let result = self
            .attacker
            .call(self.contract.id(), method_names::SUBMIT_PARTICIPANT_INFO)
            .args_json(json!({
                "proposed_participant_attestation":
                    dtos::Attestation::Mock(dtos::MockAttestation::Valid),
                "tls_public_key": fabricated_tls_key(index, marker),
            }))
            .gas(FILL_TX_GAS)
            .transact()
            .await?;
        Ok(result.is_success())
    }

    /// Fills `n` attacker entries (plus [`SPARE_GRANTS`] spare grants for the measured
    /// submit run), all inserted AFTER the setup participants and BEFORE the victim.
    async fn fill(&self, n: usize) -> anyhow::Result<()> {
        if n == 0 {
            return Ok(());
        }
        let grants = (n + SPARE_GRANTS) as u32;
        let root = self.worker.root_account()?;
        // Grants + gas money for ~n submissions (worst case ~0.0001 NEAR per TGas).
        let funding = NearToken::from_yoctonear(
            self.yocto(self.fee_token(u128::from(grants))) + self.yocto(NearToken::from_near(60)),
        );
        root.transfer_near(self.attacker.id(), funding)
            .await?
            .into_result()?;
        let prepay =
            prepay_attestation_grants(&self.attacker, &self.contract, self.attacker.id(), grants)
                .await?;
        anyhow::ensure!(prepay.is_success(), "fill prepay failed: {prepay:?}");

        for batch_start in (0..n).step_by(FILL_CONCURRENCY) {
            let batch: Vec<usize> =
                (batch_start..(batch_start + FILL_CONCURRENCY).min(n)).collect();
            let futures = batch.iter().map(|index| async move {
                self.submit_attacker_entry(*index, ATTACKER_TLS_MARKER)
                    .await
            });
            let results = join_all(futures).await;
            let failed: Vec<usize> = batch
                .iter()
                .zip(results)
                .filter(|(_, outcome)| !matches!(outcome, Ok(true)))
                .map(|(index, _)| *index)
                .collect();
            if failed.is_empty() {
                continue;
            }
            println!(
                "  {} fill submits failed; retrying sequentially",
                failed.len()
            );
            for index in failed {
                anyhow::ensure!(
                    self.submit_attacker_entry(index, ATTACKER_TLS_MARKER)
                        .await?,
                    "fill submit failed for attacker entry {index}"
                );
            }
        }
        Ok(())
    }

    /// Gives the victim the LAST map position (fresh TLS key submitted after the fill),
    /// mirroring a node onboarding or migrating behind an attacker flood.
    async fn submit_victim_attestation(&self) -> anyhow::Result<()> {
        let result = prepay_and_submit_participant_info(
            &self.victim,
            &self.contract,
            &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
            &self.victim_tls_key,
        )
        .await?;
        anyhow::ensure!(
            result.is_success(),
            "victim attestation submission failed: {result:?}"
        );
        Ok(())
    }

    async fn measure(&self, n: usize) -> anyhow::Result<FillLevelMeasurement> {
        self.fill(n).await?;
        self.submit_victim_attestation().await?;

        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Ethereum]).into();
        let register = measure_op(
            &self.victim,
            &self.contract,
            method_names::REGISTER_FOREIGN_CHAINS_CONFIG,
            json!({ "foreign_chains_config": foreign_chains_config }),
            3,
            None,
        )
        .await;

        // The long standing conventional per transaction attachment; shows at which fill
        // level a node attaching "only" 300 Tgas already loses the race.
        let register_300 = measure_op(
            &self.victim,
            &self.contract,
            method_names::REGISTER_FOREIGN_CHAINS_CONFIG,
            json!({ "foreign_chains_config": foreign_chains_config }),
            3,
            Some(Gas::from_tgas(300)),
        )
        .await;

        let verify_tee = measure_op(
            &self.participants[0],
            &self.contract,
            method_names::VERIFY_TEE,
            json!({}),
            3,
            None,
        )
        .await;

        let point_lookup = measure_op(
            &self.participants[0],
            &self.contract,
            method_names::GET_ATTESTATION,
            json!({ "tls_public_key": self.victim_tls_key }),
            3,
            None,
        )
        .await;

        // A brand new entry (grant consumed), not a repeat submission.
        let submit = measure_op(
            &self.attacker,
            &self.contract,
            method_names::SUBMIT_PARTICIPANT_INFO,
            json!({
                "proposed_participant_attestation":
                    dtos::Attestation::Mock(dtos::MockAttestation::Valid),
                "tls_public_key": fabricated_tls_key(0, MEASURED_SUBMIT_TLS_MARKER),
            }),
            1,
            None,
        )
        .await;

        Ok(FillLevelMeasurement {
            n_attacker_entries: n,
            fee_millinear: self.attestation_storage_fee_millinear,
            register,
            register_300,
            verify_tee,
            point_lookup,
            submit,
        })
    }
}

fn ggas(gas: Option<u64>) -> String {
    match gas {
        Some(g) => format!("{:.2}", g as f64 / 1e12),
        None => "-".to_string(),
    }
}

fn print_row(m: &FillLevelMeasurement) {
    println!(
        "| {:>5} | {:>12} | {:>12} | {:>10} | {:>10} | {:>8} | {} | reg300 {}",
        m.n_attacker_entries,
        ggas(m.register.median_gas()),
        ggas(m.register_300.median_gas()),
        ggas(m.verify_tee.median_gas()),
        ggas(m.point_lookup.median_gas()),
        ggas(m.submit.median_gas()),
        m.register.status(),
        if m.register_300.error.is_some() {
            "FAIL"
        } else {
            "ok"
        },
    );
}

/// Smoke run of the harness at a small fill level; asserts the measured ops succeed, the
/// grant bookkeeping matches the design, and the point lookup finds the victim's entry.
#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn attestation_scan_gas_curve_smoke() -> anyhow::Result<()> {
    let env = setup_bench_env().await?;
    let m = env.measure(10).await?;

    let register = m.register.median_gas().expect("register must produce gas");
    anyhow::ensure!(m.register.error.is_none(), "register failed: {register}");
    anyhow::ensure!(
        m.register_300.error.is_none(),
        "register@300Tgas failed: {:?}",
        m.register_300.error
    );
    anyhow::ensure!(
        m.verify_tee.error.is_none(),
        "verify_tee failed: {:?}",
        m.verify_tee.error
    );
    anyhow::ensure!(
        m.point_lookup.error.is_none(),
        "point lookup failed: {:?}",
        m.point_lookup.error
    );
    anyhow::ensure!(
        m.submit.error.is_none(),
        "submit failed: {:?}",
        m.submit.error
    );

    // Attacker prepaid 10 + 3 grants, spent 10 fill + 1 measured submit.
    let grants_left = available_attestation_grants(&env.contract, env.attacker.id()).await?;
    anyhow::ensure!(
        grants_left == SPARE_GRANTS as u32 - 1,
        "expected {} spare grants, got {grants_left}",
        SPARE_GRANTS - 1
    );

    let stored = get_participant_attestation(&env.contract, &env.victim_tls_key).await?;
    anyhow::ensure!(stored.is_some(), "victim attestation must be stored");
    Ok(())
}

/// Sweeps the fill levels, finds the smallest N where `register_foreign_chains_config`
/// fails, refines by bisection, and prints the fill-economics summary.
#[tokio::test]
#[ignore = "heavy sandbox benchmark; run explicitly"]
async fn attestation_scan_gas_curve_sweep() -> anyhow::Result<()> {
    println!(
        "|     N | register Tgas (max gas) | reg @300Tgas | verify_tee | point look | submit | register status | reg300"
    );
    let mut rows: Vec<FillLevelMeasurement> = Vec::new();
    let mut last_ok: Option<usize> = None;
    let mut first_fail: Option<usize> = None;

    for n in sweep_ns() {
        if first_fail.is_some() {
            break;
        }
        let env = setup_bench_env().await?;
        let measurement = env.measure(n).await?;
        if measurement.register.error.is_some() {
            first_fail = Some(n);
        } else {
            last_ok = Some(n);
        }
        print_row(&measurement);
        rows.push(measurement);
    }

    if let (Some(mut lo), Some(mut hi)) = (last_ok, first_fail) {
        let mut bisections_done = 0;
        while hi - lo > BISECT_RESOLUTION && bisections_done < MAX_BISECTIONS {
            let mid = (lo + hi) / 2;
            let env = setup_bench_env().await?;
            bisections_done += 1;
            let measurement = env.measure(mid).await?;
            if measurement.register.error.is_some() {
                hi = mid;
            } else {
                lo = mid;
            }
            print_row(&measurement);
            rows.push(measurement);
        }

        let failing = rows
            .iter()
            .rev()
            .find(|row| row.n_attacker_entries == hi)
            .expect("failing level must be recorded");
        println!("\n=== N_max = {hi} (smallest measured failing N); last passing N = {lo} ===");
        println!("failing register error: {}", failing.register.status());
        println!(
            "failing register total_gas_burnt: {} Tgas",
            failing
                .register
                .median_gas()
                .map(|g| g / 1_000_000_000_000)
                .map_or("-".to_string(), |t| t.to_string())
        );

        // Per-entry marginal cost from the two highest passing fill levels.
        let passing: Vec<&FillLevelMeasurement> = rows
            .iter()
            .filter(|row| row.n_attacker_entries > 0 && row.register.error.is_none())
            .collect();
        if passing.len() >= 2 {
            let (a, b) = (passing[passing.len() - 2], passing[passing.len() - 1]);
            let delta_gas =
                b.register.median_gas().unwrap_or(0) - a.register.median_gas().unwrap_or(0);
            let delta_n = (b.n_attacker_entries - a.n_attacker_entries) as f64;
            println!(
                "measured scan slope between N={} and N={}: {:.3} Tgas per attacker entry",
                a.n_attacker_entries,
                b.n_attacker_entries,
                delta_gas as f64 / delta_n / 1e12
            );
        }

        let fee = u128::from(failing.fee_millinear);
        let attacker_grants = u128::try_from(hi).unwrap() + SPARE_GRANTS as u128;
        println!(
            "fill to N_max: 1 prepay tx + {hi} submit txs (batched {}-wide) + 1 spare submit",
            FILL_CONCURRENCY
        );
        println!(
            "attacker NEAR locked in grants: {attacker_grants} grants x {fee} millinear = {:.3} NEAR",
            NearToken::from_millinear(fee * attacker_grants).as_yoctonear() as f64 / 1e24
        );
        println!(
            "Mock(Valid) attestations expire after DEFAULT_EXPIRATION_DURATION_SECONDS = 7 days \
             (604800 s); clean_invalid_attestations(max_scan) is permissionless and returns one \
             grant to the owner of each swept entry as reusable credit (the NEAR itself is not \
             withdrawable), so refilling after a sweep costs no new NEAR; the pressure is \
             renewable."
        );
    } else if first_fail.is_none() {
        let highest = rows.last().map(|row| row.n_attacker_entries).unwrap_or(0);
        println!("\nregister still passing at the highest measured N = {highest}");
    }
    Ok(())
}
