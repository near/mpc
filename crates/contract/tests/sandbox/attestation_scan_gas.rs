#![expect(non_snake_case)]

//! Sandbox gas benchmarks for attestation handling while attacker entries fill
//! `stored_attestations`. They call public endpoints only, so the same file measures any
//! contract build.
//!
//! Attacker entries sit after the setup participants and before the victim's entry, the
//! costliest position for a caller lookup that scans the map in insertion order.
//!
//! Run explicitly, for example
//! `nix develop -c cargo test --profile test-release -p mpc-contract --test test attestation_scan_gas_curve_sweep -- --ignored --nocapture`.
//! Fill levels are overridable with comma separated lists in `ATTESTATION_SCAN_SWEEP_NS`,
//! `ATTESTATION_AB_NS`, `ATTESTATION_CLEAN_NS` and `ATTESTATION_UPGRADE_NS`. The expired entry
//! counts of the cleanup bench are overridable the same way in `ATTESTATION_CLEAN_EXPIRED`.

use crate::sandbox::common::{gen_accounts, init_contract_running, make_threshold_params};
use crate::sandbox::utils::consts::GAS_FOR_INIT;
use crate::sandbox::utils::contract_build::current_contract;
use crate::sandbox::utils::mpc_contract::{
    available_attestation_grants, get_config, get_participant_attestation, get_tee_accounts,
    prepay_and_submit_participant_info, prepay_attestation_grants, submit_participant_info,
    vote_tee_verifier_change,
};
use crate::sandbox::utils::shared_key_utils::new_secp256k1;
use crate::sandbox::utils::transactions::CallMpcContract;
use futures::future::join_all;
use mpc_contract::primitives::participants::{ParticipantInfo, Participants};
use mpc_contract::primitives::test_utils::bogus_tee_verifier_account_id;
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_mpc_contract_interface::{method_names, types as dtos};
use near_primitives::hash::CryptoHash;
use near_primitives::views::TxExecutionStatus;
use near_sdk::Gas;
use near_workspaces::result::ExecutionOutcome;
use near_workspaces::types::{AccessKey, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract};
use serde_json::json;
use std::collections::BTreeSet;
use test_utils::sandbox::SandboxWorker;

const SETUP_PARTICIPANTS: usize = 4;
const SWEEP_NS: &[usize] = &[
    0, 10, 50, 100, 250, 500, 1000, 1500, 2000, 3000, 4000, 5000, 6000,
];
const AB_NS: &[usize] = &[0, 100];
const UPGRADE_NS: &[usize] = &[0, 100];
const CLEAN_NS: &[usize] = &[0, 100];
const CLEAN_EXPIRED: &[usize] = &[CLEAN_PRODUCTION_MAX_SCAN as usize];
/// Covers every new entry submission a test measures after the fill.
const SPARE_GRANTS: usize = 3;
const FILL_CONCURRENCY: usize = 50;
const BISECT_RESOLUTION: usize = 100;
const MAX_BISECTIONS: usize = 4;
const FILL_TX_GAS: Gas = Gas::from_tgas(100);
/// Gas that nodes conventionally attach.
const CONVENTIONAL_TX_GAS: Gas = Gas::from_tgas(300);
const RUNS: usize = 3;
/// The bound of the sweep after a reshare, so the floor row matches production.
const CLEAN_PRODUCTION_MAX_SCAN: u32 = 30;
const CLEAN_FULL_SCAN_MAX_SCAN: u32 = 10_000;
/// A raised post reshare cleanup budget, tried after the configured one runs out.
const RAISED_CLEAN_BUDGET: Gas = Gas::from_tgas(25);
const ATTESTATION_EXPIRY_SECONDS: u64 = 60;
const EXPIRY_FAST_FORWARD_BLOCKS: u64 = 50;
/// `migrate` logs this first, so it marks the upgrade receipt.
const MIGRATE_LOG: &str = "migrating contract";

const PARTICIPANT_TLS_MARKER: u8 = 0x01;
const VICTIM_TLS_MARKER: u8 = 0x02;
const ATTACKER_TLS_MARKER: u8 = 0xAA;
const MEASURED_SUBMIT_TLS_MARKER: u8 = 0xBB;
const EXPIRING_TLS_MARKER: u8 = 0xCC;

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

    fn short_status(&self) -> &'static str {
        if self.error.is_some() { "FAIL" } else { "ok" }
    }
}

struct FillLevelMeasurement {
    n_attacker_entries: usize,
    fee_millinear: u64,
    register: OpMeasurement,
    register_300: OpMeasurement,
    verify_tee: OpMeasurement,
    point_lookup: OpMeasurement,
    submit: OpMeasurement,
}

fn fabricated_tls_key(index: usize, marker: u8) -> dtos::Ed25519PublicKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[8] = marker;
    dtos::Ed25519PublicKey::from(bytes)
}

fn ns_from_env(var: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(var) {
        Ok(s) => s
            .split(',')
            .filter_map(|part| part.trim().parse().ok())
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn failure_reason(failures: &[&ExecutionOutcome]) -> String {
    let text = failures
        .iter()
        .map(|outcome| format!("{outcome:?}"))
        .collect::<Vec<_>>()
        .join(" | ");
    // The guest message sits in `ExecutionError("...")` at the end of a long debug dump.
    text.match_indices("ExecutionError(\"")
        .next()
        .and_then(|(index, _)| {
            let start = index + "ExecutionError(\"".len();
            text[start..]
                .find('"')
                .map(|end| text[start..start + end].to_string())
        })
        .unwrap_or_else(|| {
            let mut truncated = text.clone();
            truncated.truncate(300);
            truncated
        })
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
    let error = result
        .into_result()
        .err()
        .map(|failure| failure_reason(&failure.failures()));
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

#[derive(Clone, Copy)]
enum InitialContract {
    Current,
    /// The production binary, upgraded to [`current_contract`] by the test.
    Production,
}

struct BenchEnv {
    worker: SandboxWorker,
    contract: Contract,
    participants: Vec<Account>,
    victim: Account,
    attacker: Account,
    victim_tls_key: dtos::Ed25519PublicKey,
    attestation_storage_fee_millinear: u64,
}

/// Four setup participants plus the victim, each under its own fabricated TLS key.
fn bench_threshold_set(participants: &[Account], victim: &Account) -> anyhow::Result<Participants> {
    let mut threshold_set = Participants::new();
    for (index, account) in participants.iter().enumerate() {
        threshold_set.insert(
            account.id().clone(),
            ParticipantInfo {
                url: "127.0.0.1".try_into().unwrap(),
                tls_public_key: fabricated_tls_key(index, PARTICIPANT_TLS_MARKER),
            },
        )?;
    }
    threshold_set.insert(
        victim.id().clone(),
        ParticipantInfo {
            url: "127.0.0.1".try_into().unwrap(),
            tls_public_key: fabricated_tls_key(0, VICTIM_TLS_MARKER),
        },
    )?;
    Ok(threshold_set)
}

fn bench_domains_and_keyset() -> (Vec<dtos::DomainConfig>, dtos::Keyset) {
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
    (domains, dtos::Keyset::new(dtos::EpochId::new(1), vec![key]))
}

/// A running contract with the four setup participants attested, in insertion order.
async fn setup_bench_env(initial_contract: InitialContract) -> anyhow::Result<BenchEnv> {
    let worker = test_utils::sandbox::start_sandbox().await?;
    let wasm = match initial_contract {
        InitialContract::Current => current_contract(),
        InitialContract::Production => contract_history::current_mainnet(),
    };
    let contract = worker.dev_deploy(wasm).await?;
    let (accounts, _) = gen_accounts(&worker, SETUP_PARTICIPANTS + 2).await;
    let (participants, victim, attacker) = (
        accounts[..SETUP_PARTICIPANTS].to_vec(),
        accounts[SETUP_PARTICIPANTS].clone(),
        accounts[SETUP_PARTICIPANTS + 1].clone(),
    );

    // Submitting under the genesis TLS key would overwrite the victim's genesis entry in
    // place, ahead of the fill. A fresh key appends its entry after the fill instead.
    let victim_tls_key = fabricated_tls_key(1, VICTIM_TLS_MARKER);

    let threshold_params = make_threshold_params(&bench_threshold_set(&participants, &victim)?);
    let (domains, keyset) = bench_domains_and_keyset();
    init_contract_running(&contract, domains, 1, keyset, threshold_params, None).await;

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

    if matches!(initial_contract, InitialContract::Production) {
        // Production init ignores the verifier argument, and migrating requires one.
        vote_tee_verifier_change(&participants, &contract, &bogus_tee_verifier_account_id())
            .await?;
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

fn expiring_mock(expiry_timestamp_seconds: u64) -> dtos::Attestation {
    dtos::Attestation::Mock(dtos::MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp_seconds),
        expected_measurements: None,
    })
}

async fn chain_time_seconds(worker: &SandboxWorker) -> anyhow::Result<u64> {
    Ok(worker.view_block().await?.timestamp() / 1_000_000_000)
}

struct CleanRun {
    total_gas: u64,
    receipt_gas: Option<u64>,
    execution_gas: Option<u64>,
    removed: Option<u32>,
    error: Option<String>,
}

fn foreign_chains_config_args() -> serde_json::Value {
    let foreign_chains_config: dtos::ForeignChainsConfig =
        BTreeSet::from([dtos::ForeignChain::Ethereum]).into();
    json!({ "foreign_chains_config": foreign_chains_config })
}

fn mock_submission_args(tls_public_key: &dtos::Ed25519PublicKey) -> serde_json::Value {
    json!({
        "proposed_participant_attestation": dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        "tls_public_key": tls_public_key,
    })
}

impl BenchEnv {
    fn fee_token(&self, grants: u128) -> NearToken {
        NearToken::from_millinear(u128::from(self.attestation_storage_fee_millinear) * grants)
    }

    async fn submit_attacker_entry(&self, index: usize) -> anyhow::Result<bool> {
        let result = self
            .attacker
            .call(self.contract.id(), method_names::SUBMIT_PARTICIPANT_INFO)
            .args_json(mock_submission_args(&fabricated_tls_key(
                index,
                ATTACKER_TLS_MARKER,
            )))
            .gas(FILL_TX_GAS)
            .transact()
            .await?;
        Ok(result.is_success())
    }

    /// Stores `n` attacker entries and leaves the attacker [`SPARE_GRANTS`] grants.
    async fn fill(&self, n: usize) -> anyhow::Result<()> {
        let grants = (n + SPARE_GRANTS) as u32;
        let root = self.worker.root_account()?;
        let funding = NearToken::from_yoctonear(
            self.fee_token(u128::from(grants)).as_yoctonear()
                + NearToken::from_near(10 + (n as u128) / 20).as_yoctonear(),
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
            let results =
                join_all(batch.iter().map(|index| self.submit_attacker_entry(*index))).await;
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
                "  {} fill submits failed, retrying sequentially",
                failed.len()
            );
            for index in failed {
                anyhow::ensure!(
                    self.submit_attacker_entry(index).await?,
                    "fill submit failed for attacker entry {index}"
                );
            }
        }
        Ok(())
    }

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

    /// Fills the first [`CLEAN_PRODUCTION_MAX_SCAN`] map positions, the first `expired` of
    /// them with entries that expire together. Each sits under its own account key, so every
    /// removal also drops an index row. Returns the expiry.
    async fn store_scan_prefix(&self, expired: usize) -> anyhow::Result<u64> {
        anyhow::ensure!(
            expired <= CLEAN_PRODUCTION_MAX_SCAN as usize,
            "at most {CLEAN_PRODUCTION_MAX_SCAN} entries fit the scan bound, got {expired}"
        );
        let expiry = chain_time_seconds(&self.worker).await? + ATTESTATION_EXPIRY_SECONDS;
        let attestation_at = |position: usize| {
            if position < expired {
                expiring_mock(expiry)
            } else {
                dtos::Attestation::Mock(dtos::MockAttestation::Valid)
            }
        };

        // The threshold entries hold the first positions, so they are overwritten in place.
        let threshold_entries = self
            .participants
            .iter()
            .enumerate()
            .map(|(index, account)| (account, fabricated_tls_key(index, PARTICIPANT_TLS_MARKER)))
            .chain([(&self.victim, fabricated_tls_key(0, VICTIM_TLS_MARKER))]);
        let threshold_count = SETUP_PARTICIPANTS + 1;
        for (position, (account, tls_key)) in threshold_entries.enumerate() {
            let result = submit_participant_info(
                account,
                &self.contract,
                &attestation_at(position),
                &tls_key,
            )
            .await?;
            anyhow::ensure!(
                result.is_success(),
                "expiring overwrite failed for {}: {}",
                account.id(),
                failure_reason(&result.failures())
            );
        }

        let attacker_entries = CLEAN_PRODUCTION_MAX_SCAN as usize - threshold_count;
        let signing_keys: Vec<SecretKey> = (0..attacker_entries)
            .map(|_| SecretKey::from_random(KeyType::ED25519))
            .collect();
        signing_keys
            .iter()
            .fold(self.attacker.batch(self.attacker.id()), |batch, key| {
                batch.add_key(key.public_key(), AccessKey::full_access())
            })
            .transact()
            .await?
            .into_result()?;
        let root = self.worker.root_account()?;
        let funding = NearToken::from_yoctonear(
            self.fee_token(attacker_entries as u128).as_yoctonear()
                + NearToken::from_near(5).as_yoctonear(),
        );
        root.transfer_near(self.attacker.id(), funding)
            .await?
            .into_result()?;
        let prepay = prepay_attestation_grants(
            &self.attacker,
            &self.contract,
            self.attacker.id(),
            attacker_entries as u32,
        )
        .await?;
        anyhow::ensure!(prepay.is_success(), "expiring prepay failed: {prepay:?}");

        let submissions: Vec<(Account, dtos::Ed25519PublicKey, dtos::Attestation)> = signing_keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                (
                    Account::from_secret_key(self.attacker.id().clone(), key, &*self.worker),
                    fabricated_tls_key(index, EXPIRING_TLS_MARKER),
                    attestation_at(threshold_count + index),
                )
            })
            .collect();
        // Concurrent submissions land in any order, so the expiring group goes first.
        let (expiring, valid): (Vec<_>, Vec<_>) = submissions
            .iter()
            .enumerate()
            .partition(|(index, _)| threshold_count + index < expired);
        for group in [expiring, valid] {
            let results = join_all(group.iter().map(|(_, (signer, tls_key, attestation))| {
                submit_participant_info(signer, &self.contract, attestation, tls_key)
            }))
            .await;
            for result in results {
                let result = result?;
                anyhow::ensure!(
                    result.is_success(),
                    "attacker scan prefix entry failed: {}",
                    failure_reason(&result.failures())
                );
            }
        }
        Ok(expiry)
    }

    async fn wait_until_expired(&self, expiry: u64) -> anyhow::Result<()> {
        while chain_time_seconds(&self.worker).await? <= expiry {
            self.worker.fast_forward(EXPIRY_FAST_FORWARD_BLOCKS).await?;
        }
        Ok(())
    }

    async fn clean_at_production_bound(
        &self,
        attached_gas: Option<Gas>,
    ) -> anyhow::Result<CleanRun> {
        let call = self
            .attacker
            .call(self.contract.id(), method_names::CLEAN_INVALID_ATTESTATIONS)
            .args_json(json!({ "max_scan": CLEAN_PRODUCTION_MAX_SCAN }));
        let call = match attached_gas {
            Some(gas) => call.gas(gas),
            None => call.max_gas(),
        };
        let result = call.transact().await?;
        let total_gas = result.total_gas_burnt.as_gas();
        // The attached gas bounds this receipt, the one the post reshare promise creates.
        let receipt = result.receipt_outcomes().first();
        let receipt_gas = receipt.map(|outcome| outcome.gas_burnt.as_gas());
        let execution_gas = match receipt {
            Some(receipt) => receipt_gas_profile(
                &self.worker,
                result.outcome().transaction_hash.0,
                self.attacker.id(),
                receipt.transaction_hash.0,
            )
            .await
            .ok()
            .map(|profile| profile.execution),
            None => None,
        };
        let (removed, error) = match result.into_result() {
            Ok(success) => (Some(success.json::<u32>()?), None),
            Err(failure) => (None, Some(failure_reason(&failure.failures()))),
        };
        Ok(CleanRun {
            total_gas,
            receipt_gas,
            execution_gas,
            removed,
            error,
        })
    }

    async fn register_victim(&self, attached_gas: Option<Gas>) -> OpMeasurement {
        measure_op(
            &self.victim,
            &self.contract,
            method_names::REGISTER_FOREIGN_CHAINS_CONFIG,
            foreign_chains_config_args(),
            RUNS,
            attached_gas,
        )
        .await
    }

    /// Resubmits the victim's TLS key, an overwrite that consumes no grant.
    async fn re_attest_victim(&self, runs: usize) -> OpMeasurement {
        measure_op(
            &self.victim,
            &self.contract,
            method_names::SUBMIT_PARTICIPANT_INFO,
            mock_submission_args(&self.victim_tls_key),
            runs,
            None,
        )
        .await
    }

    async fn measure(&self, n: usize) -> anyhow::Result<FillLevelMeasurement> {
        self.fill(n).await?;
        self.submit_victim_attestation().await?;

        let register = self.register_victim(None).await;
        let register_300 = self.register_victim(Some(CONVENTIONAL_TX_GAS)).await;
        let verify_tee = measure_op(
            &self.participants[0],
            &self.contract,
            method_names::VERIFY_TEE,
            json!({}),
            RUNS,
            None,
        )
        .await;
        let point_lookup = measure_op(
            &self.participants[0],
            &self.contract,
            method_names::GET_ATTESTATION,
            json!({ "tls_public_key": self.victim_tls_key }),
            RUNS,
            None,
        )
        .await;
        let submit = measure_op(
            &self.attacker,
            &self.contract,
            method_names::SUBMIT_PARTICIPANT_INFO,
            mock_submission_args(&fabricated_tls_key(0, MEASURED_SUBMIT_TLS_MARKER)),
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

    /// Production predates the vote then submit API, so the upgrade takes its proposal
    /// flow. Both flows deploy and migrate in one receipt with
    /// `contract_upgrade_deposit_tera_gas` attached.
    #[expect(deprecated)]
    async fn upgrade_to_current_contract(&self) -> anyhow::Result<UpgradeOutcome> {
        let new_code = current_contract();
        let proposal = self.participants[0]
            .call_mpc(self.contract.id())
            .propose_update(dtos::ProposeUpdateArgs {
                code: Some(new_code.to_vec()),
                config: None,
            })
            .await?;
        anyhow::ensure!(
            proposal.is_success(),
            "propose_update failed: {}",
            failure_reason(&proposal.failures())
        );
        let update_id: dtos::UpdateId = proposal.json()?;

        let mut applying_vote = None;
        for voter in &self.participants {
            let vote = voter
                .call_mpc(self.contract.id())
                .vote_update(update_id)
                .await?;
            let applied: bool = vote.clone().json()?;
            if applied {
                applying_vote = Some((voter, vote));
                break;
            }
        }
        let (voter, vote) =
            applying_vote.ok_or_else(|| anyhow::anyhow!("no vote applied the update"))?;

        // The first receipt on the contract is the vote itself.
        let contract_receipts: Vec<&ExecutionOutcome> = vote
            .receipt_outcomes()
            .iter()
            .filter(|outcome| outcome.executor_id == *self.contract.id())
            .collect();
        let upgrade_receipt = contract_receipts
            .iter()
            .find(|outcome| outcome.logs.iter().any(|log| log.contains(MIGRATE_LOG)))
            .or_else(|| contract_receipts.get(1))
            .copied();
        let Some(upgrade_receipt) = upgrade_receipt else {
            return Ok(UpgradeOutcome {
                error: Some("no upgrade receipt".to_string()),
                receipt_gas: None,
                profile: None,
            });
        };

        let profile = match receipt_gas_profile(
            &self.worker,
            vote.outcome().transaction_hash.0,
            voter.id(),
            upgrade_receipt.transaction_hash.0,
        )
        .await
        {
            Ok(profile) => Some(profile),
            Err(err) => {
                println!("  gas profile unavailable: {err}");
                None
            }
        };
        let code_replaced = self.contract.view_code().await? == new_code;
        let error = if !upgrade_receipt.is_success() {
            Some(failure_reason(&vote.failures()))
        } else if !code_replaced {
            Some("code was not replaced".to_string())
        } else {
            None
        };
        Ok(UpgradeOutcome {
            error,
            receipt_gas: Some(upgrade_receipt.gas_burnt.as_gas()),
            profile,
        })
    }
}

/// Covers the receipt's function call execution, the part its attached gas bounds. The fees
/// the receipt burns for its own actions fall outside it.
struct GasProfile {
    execution: u64,
    /// Largest entries first.
    entries: Vec<(String, u64)>,
}

async fn receipt_gas_profile(
    worker: &SandboxWorker,
    tx_hash: [u8; 32],
    sender: &AccountId,
    receipt_id: [u8; 32],
) -> anyhow::Result<GasProfile> {
    let response = JsonRpcClient::connect(worker.rpc_addr())
        .call(
            methods::EXPERIMENTAL_tx_status::RpcTransactionStatusRequest {
                transaction_info: methods::EXPERIMENTAL_tx_status::TransactionInfo::TransactionId {
                    tx_hash: CryptoHash(tx_hash),
                    sender_account_id: sender.clone(),
                },
                wait_until: TxExecutionStatus::Executed,
            },
        )
        .await
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    let receipt = response
        .final_execution_outcome
        .ok_or_else(|| anyhow::anyhow!("no final outcome"))?
        .into_outcome()
        .receipts_outcome
        .into_iter()
        .find(|receipt| receipt.id == CryptoHash(receipt_id))
        .ok_or_else(|| anyhow::anyhow!("upgrade receipt missing from the status response"))?;
    let mut entries: Vec<(String, u64)> = receipt
        .outcome
        .metadata
        .gas_profile
        .unwrap_or_default()
        .into_iter()
        .map(|cost| (cost.cost, cost.gas_used.as_gas()))
        .filter(|(_, gas)| *gas > 0)
        .collect();
    entries.sort_by_key(|(_, gas)| std::cmp::Reverse(*gas));
    Ok(GasProfile {
        execution: entries.iter().map(|(_, gas)| gas).sum(),
        entries,
    })
}

fn tgas(gas: Option<u64>) -> String {
    match gas {
        Some(g) => format!("{:.2}", g as f64 / 1e12),
        None => "-".to_string(),
    }
}

fn print_header() {
    println!(
        "|     N | register, max gas | register, 300 Tgas | verify_tee | get_attestation | new entry submit | register status | 300 Tgas status |"
    );
    println!("|---|---|---|---|---|---|---|---|");
}

fn print_row(m: &FillLevelMeasurement) {
    println!(
        "| {:>5} | {:>8} | {:>8} | {:>6} | {:>6} | {:>6} | {} | {} |",
        m.n_attacker_entries,
        tgas(m.register.median_gas()),
        tgas(m.register_300.median_gas()),
        tgas(m.verify_tee.median_gas()),
        tgas(m.point_lookup.median_gas()),
        tgas(m.submit.median_gas()),
        m.register.status(),
        m.register_300.short_status(),
    );
}

#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn attestation_scan_gas_curve_smoke() -> anyhow::Result<()> {
    let env = setup_bench_env(InitialContract::Current).await?;
    let m = env.measure(10).await?;
    print_header();
    print_row(&m);

    for (name, op) in [
        ("register", &m.register),
        ("register at 300 Tgas", &m.register_300),
        ("verify_tee", &m.verify_tee),
        ("get_attestation", &m.point_lookup),
        ("new entry submit", &m.submit),
    ] {
        anyhow::ensure!(op.error.is_none(), "{name} failed: {}", op.status());
    }

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

fn fails_with_max_gas(row: &FillLevelMeasurement) -> bool {
    row.register.error.is_some()
}

fn fails_with_conventional_gas(row: &FillLevelMeasurement) -> bool {
    row.register_300.error.is_some()
}

async fn bisect_failure(
    rows: &mut Vec<FillLevelMeasurement>,
    mut passing: usize,
    mut failing: usize,
    fails: fn(&FillLevelMeasurement) -> bool,
) -> anyhow::Result<(usize, usize)> {
    let mut rounds = 0;
    while failing - passing > BISECT_RESOLUTION && rounds < MAX_BISECTIONS {
        let mid = (passing + failing) / 2;
        let row = setup_bench_env(InitialContract::Current)
            .await?
            .measure(mid)
            .await?;
        print_row(&row);
        if fails(&row) {
            failing = mid;
        } else {
            passing = mid;
        }
        rows.push(row);
        rounds += 1;
    }
    Ok((passing, failing))
}

/// Sweeps the fill levels until `register_foreign_chains_config` fails even with max gas,
/// then bisects the failure points with max gas and with the conventional 300 Tgas.
#[tokio::test]
#[ignore = "heavy sandbox benchmark; run explicitly"]
async fn attestation_scan_gas_curve_sweep() -> anyhow::Result<()> {
    print_header();
    let mut rows: Vec<FillLevelMeasurement> = Vec::new();
    for n in ns_from_env("ATTESTATION_SCAN_SWEEP_NS", SWEEP_NS) {
        let row = setup_bench_env(InitialContract::Current)
            .await?
            .measure(n)
            .await?;
        print_row(&row);
        let hit_the_cap = fails_with_max_gas(&row);
        rows.push(row);
        if hit_the_cap {
            break;
        }
    }

    let mut boundaries = Vec::new();
    for (label, fails) in [
        (
            "register, max gas",
            fails_with_max_gas as fn(&FillLevelMeasurement) -> bool,
        ),
        ("register, 300 Tgas", fails_with_conventional_gas),
    ] {
        let Some(first_failing) = rows
            .iter()
            .filter(|row| fails(row))
            .map(|row| row.n_attacker_entries)
            .min()
        else {
            boundaries.push(format!("{label}: passes at every measured N"));
            continue;
        };
        let Some(last_passing) = rows
            .iter()
            .filter(|row| !fails(row) && row.n_attacker_entries < first_failing)
            .map(|row| row.n_attacker_entries)
            .max()
        else {
            boundaries.push(format!("{label}: fails already at N={first_failing}"));
            continue;
        };
        let (passing, failing) =
            bisect_failure(&mut rows, last_passing, first_failing, fails).await?;
        let fee_millinear = rows[0].fee_millinear;
        let grants = (failing + SPARE_GRANTS) as u128;
        boundaries.push(format!(
            "{label}: passes at N={passing}, fails at N={failing}, attacker locks {:.3} NEAR in {grants} grants",
            NearToken::from_millinear(u128::from(fee_millinear) * grants).as_yoctonear() as f64
                / 1e24
        ));
    }

    rows.sort_by_key(|row| row.n_attacker_entries);
    println!("\nAll rows, sorted by N:");
    print_header();
    for row in &rows {
        print_row(row);
    }
    println!();
    for boundary in &boundaries {
        println!("{boundary}");
    }

    let passing: Vec<&FillLevelMeasurement> =
        rows.iter().filter(|row| !fails_with_max_gas(row)).collect();
    if let (Some(low), Some(high)) = (passing.first(), passing.last())
        && high.n_attacker_entries > low.n_attacker_entries
    {
        let delta_gas = high.register.median_gas().unwrap_or(0) as f64
            - low.register.median_gas().unwrap_or(0) as f64;
        let delta_n = (high.n_attacker_entries - low.n_attacker_entries) as f64;
        println!(
            "register slope between N={} and N={}: {:.4} Tgas per attacker entry",
            low.n_attacker_entries,
            high.n_attacker_entries,
            delta_gas / delta_n / 1e12
        );
    }
    Ok(())
}

struct AbMeasurement {
    n_attacker_entries: usize,
    new_entry: OpMeasurement,
    re_attestation: OpMeasurement,
    clean_production: OpMeasurement,
    clean_full_scan: OpMeasurement,
}

impl AbMeasurement {
    fn ops(&self) -> [(&'static str, &OpMeasurement); 4] {
        [
            ("new entry", &self.new_entry),
            ("reattestation", &self.re_attestation),
            ("clean at the production scan bound", &self.clean_production),
            ("clean over the whole map", &self.clean_full_scan),
        ]
    }
}

fn print_ab_row(m: &AbMeasurement) {
    println!(
        "| {:>5} | {:>6} | {:>6} | {:>6} | {:>6} | {} |",
        m.n_attacker_entries,
        tgas(m.new_entry.median_gas()),
        tgas(m.re_attestation.median_gas()),
        tgas(m.clean_production.median_gas()),
        tgas(m.clean_full_scan.median_gas()),
        m.ops()
            .iter()
            .map(|(_, op)| op.short_status())
            .collect::<Vec<_>>()
            .join(" "),
    );
}

/// The write paths and the `clean_invalid_attestations` floor with nothing to remove.
#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn attestation_ab_gas_curve() -> anyhow::Result<()> {
    println!(
        "|     N | new entry | reattestation | clean, max_scan 30 | clean, whole map | statuses |"
    );
    println!("|---|---|---|---|---|---|");
    for n in ns_from_env("ATTESTATION_AB_NS", AB_NS) {
        let env = setup_bench_env(InitialContract::Current).await?;
        env.fill(n).await?;
        env.submit_victim_attestation().await?;

        let clean_production = measure_op(
            &env.attacker,
            &env.contract,
            method_names::CLEAN_INVALID_ATTESTATIONS,
            json!({ "max_scan": CLEAN_PRODUCTION_MAX_SCAN }),
            RUNS,
            None,
        )
        .await;
        let clean_full_scan = measure_op(
            &env.attacker,
            &env.contract,
            method_names::CLEAN_INVALID_ATTESTATIONS,
            json!({ "max_scan": CLEAN_FULL_SCAN_MAX_SCAN }),
            RUNS,
            None,
        )
        .await;
        let re_attestation = env.re_attest_victim(RUNS).await;

        let mut new_entry = OpMeasurement {
            gas_samples: Vec::with_capacity(RUNS),
            error: None,
        };
        for index in 0..RUNS {
            let (gas, error) = record_run(
                &env.attacker,
                &env.contract,
                method_names::SUBMIT_PARTICIPANT_INFO,
                mock_submission_args(&fabricated_tls_key(index, MEASURED_SUBMIT_TLS_MARKER)),
                None,
            )
            .await;
            new_entry.gas_samples.push(gas);
            if new_entry.error.is_none() {
                new_entry.error = error;
            }
        }

        let m = AbMeasurement {
            n_attacker_entries: n,
            new_entry,
            re_attestation,
            clean_production,
            clean_full_scan,
        };
        print_ab_row(&m);
        for (name, op) in m.ops() {
            anyhow::ensure!(
                op.error.is_none(),
                "{name} failed at N={n}: {}",
                op.status()
            );
        }

        // A sweep that removed an entry or returned a grant would skew the rows.
        let threshold_entries = SETUP_PARTICIPANTS + 1;
        let expected_entries = threshold_entries + 1 + n + RUNS;
        let stored = get_tee_accounts(&env.contract).await?;
        anyhow::ensure!(
            stored.len() == expected_entries,
            "expected {expected_entries} stored attestations, got {}",
            stored.len()
        );
        let grants_left = available_attestation_grants(&env.contract, env.attacker.id()).await?;
        anyhow::ensure!(
            grants_left == (SPARE_GRANTS - RUNS) as u32,
            "expected {} grants left after the measured runs, got {grants_left}",
            SPARE_GRANTS - RUNS
        );
    }
    Ok(())
}

struct CleanCase {
    n: usize,
    expired: usize,
    /// Every attempt in order, the last one being the first that completed.
    attempts: Vec<(Option<Gas>, CleanRun)>,
}

impl CleanCase {
    fn completed(&self) -> Option<&CleanRun> {
        self.attempts
            .last()
            .map(|(_, run)| run)
            .filter(|run| run.error.is_none())
    }

    fn fits(&self, budget: Gas) -> bool {
        self.attempts.iter().any(|(attached, run)| {
            run.error.is_none() && attached.is_some_and(|attached| attached <= budget)
        })
    }
}

fn print_clean_row(n: usize, expired: usize, attached_gas: Option<Gas>, run: &CleanRun) {
    println!(
        "| {:>5} | {:>2} | {:>6} | {:>6} | {:>6} | {:>6} | {} | {} |",
        n,
        expired,
        attached_gas.map_or("max".to_string(), |gas| tgas(Some(gas.as_gas()))),
        tgas(run.receipt_gas),
        tgas(run.execution_gas),
        tgas(Some(run.total_gas)),
        run.removed
            .map_or("-".to_string(), |removed| removed.to_string()),
        run.error
            .as_ref()
            .map_or("ok".to_string(), |err| format!("FAILED: {err}")),
    );
}

/// Cleanup at the production scan bound with the first K scanned entries expired. Each case
/// runs under the configured post reshare budget, then [`RAISED_CLEAN_BUDGET`], then max gas,
/// stopping at the first that completes. A run that runs out of gas rolls back, so every
/// attempt sees the same state.
#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn clean_invalid_attestations__should_remove_the_expired_entries_within_the_scan_bound()
-> anyhow::Result<()> {
    println!("|     N |  K | attached | receipt | execution | total | removed | status |");
    println!("|---|---|---|---|---|---|---|---|");
    let mut cases = Vec::new();
    let mut configured_budget = None;
    for expired in ns_from_env("ATTESTATION_CLEAN_EXPIRED", CLEAN_EXPIRED) {
        for n in ns_from_env("ATTESTATION_CLEAN_NS", CLEAN_NS) {
            // Given
            let env = setup_bench_env(InitialContract::Current).await?;
            let expiry = env.store_scan_prefix(expired).await?;
            env.fill(n).await?;
            env.wait_until_expired(expiry).await?;
            let budget = Gas::from_tgas(
                get_config(&env.contract)
                    .await?
                    .clean_invalid_attestations_tera_gas,
            );
            configured_budget = Some(budget);

            // When
            let mut attachments = vec![Some(budget)];
            if RAISED_CLEAN_BUDGET > budget {
                attachments.push(Some(RAISED_CLEAN_BUDGET));
            }
            attachments.push(None);
            let mut attempts = Vec::new();
            for attached_gas in attachments {
                let run = env.clean_at_production_bound(attached_gas).await?;
                print_clean_row(n, expired, attached_gas, &run);
                let completed = run.error.is_none();
                attempts.push((attached_gas, run));
                if completed {
                    break;
                }
            }
            cases.push(CleanCase {
                n,
                expired,
                attempts,
            });
        }
    }

    let configured_budget = configured_budget.expect("at least one case ran");
    println!(
        "\n|     N |  K | needed receipt | needed execution | fits {} | fits {} |",
        tgas(Some(configured_budget.as_gas())),
        tgas(Some(RAISED_CLEAN_BUDGET.as_gas()))
    );
    println!("|---|---|---|---|---|---|");
    for case in &cases {
        let completed = case.completed();
        println!(
            "| {:>5} | {:>2} | {:>6} | {:>6} | {} | {} |",
            case.n,
            case.expired,
            tgas(completed.and_then(|run| run.receipt_gas)),
            tgas(completed.and_then(|run| run.execution_gas)),
            case.fits(configured_budget),
            case.fits(RAISED_CLEAN_BUDGET),
        );
    }

    // Then
    for case in &cases {
        let removed = case.completed().and_then(|run| run.removed);
        anyhow::ensure!(
            removed == Some(case.expired as u32),
            "at N={} the sweep removed {removed:?} of {} expired entries",
            case.n,
            case.expired
        );
    }
    Ok(())
}

/// Median `total_gas_burnt` of `init_running` with the five participant threshold set.
#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn init_running_gas_curve() -> anyhow::Result<()> {
    let mut gas_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let worker = test_utils::sandbox::start_sandbox().await?;
        let contract = worker.dev_deploy(current_contract()).await?;
        let (accounts, _) = gen_accounts(&worker, SETUP_PARTICIPANTS + 1).await;
        let threshold_params = make_threshold_params(&bench_threshold_set(
            &accounts[..SETUP_PARTICIPANTS],
            &accounts[SETUP_PARTICIPANTS],
        )?);
        let (domains, keyset) = bench_domains_and_keyset();
        let init_config: Option<dtos::InitConfig> = None;

        let result = contract
            .call(method_names::INIT_RUNNING)
            .args_json(json!({
                "domains": domains,
                "next_domain_id": 1,
                "keyset": keyset,
                "parameters": dtos::GovernanceThresholdParameters::from(threshold_params),
                "tee_verifier_account_id": bogus_tee_verifier_account_id(),
                "init_config": init_config,
            }))
            .gas(GAS_FOR_INIT)
            .transact()
            .await?;
        anyhow::ensure!(result.is_success(), "init_running failed: {result:?}");
        gas_samples.push(result.total_gas_burnt.as_gas());
    }
    gas_samples.sort_unstable();
    println!(
        "init_running, 5 participants: median {} Tgas over {RUNS} deploys, samples {:?}",
        tgas(Some(gas_samples[RUNS / 2])),
        gas_samples
            .iter()
            .map(|gas| tgas(Some(*gas)))
            .collect::<Vec<_>>(),
    );
    Ok(())
}

struct UpgradeOutcome {
    error: Option<String>,
    receipt_gas: Option<u64>,
    profile: Option<GasProfile>,
}

struct PostUpgradeRegistration {
    register_stored_before_upgrade: OpMeasurement,
    re_attestation: OpMeasurement,
    register_after_re_attestation: OpMeasurement,
}

impl PostUpgradeRegistration {
    fn ops(&self) -> [(&'static str, &OpMeasurement); 3] {
        [
            (
                "register, entry stored before the upgrade",
                &self.register_stored_before_upgrade,
            ),
            ("reattestation", &self.re_attestation),
            (
                "register after reattestation",
                &self.register_after_re_attestation,
            ),
        ]
    }
}

struct UpgradeMeasurement {
    n_attacker_entries: usize,
    upgrade: UpgradeOutcome,
    after_upgrade: Option<PostUpgradeRegistration>,
}

fn print_upgrade_header() {
    println!(
        "|     N | upgrade | upgrade receipt | deploy and call fees | migrate execution | register, entry stored before upgrade | reattestation | register after reattestation | statuses |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
}

fn print_upgrade_row(m: &UpgradeMeasurement) {
    let migrate_execution = m.upgrade.profile.as_ref().map(|profile| profile.execution);
    let action_fees = m
        .upgrade
        .receipt_gas
        .zip(migrate_execution)
        .map(|(receipt, execution)| receipt - execution);
    let median = |op: fn(&PostUpgradeRegistration) -> &OpMeasurement| {
        tgas(
            m.after_upgrade
                .as_ref()
                .and_then(|after| op(after).median_gas()),
        )
    };
    println!(
        "| {:>5} | {} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {} |",
        m.n_attacker_entries,
        match &m.upgrade.error {
            None => "ok".to_string(),
            Some(err) => format!("FAILED: {err}"),
        },
        tgas(m.upgrade.receipt_gas),
        tgas(action_fees),
        tgas(migrate_execution),
        median(|after| &after.register_stored_before_upgrade),
        median(|after| &after.re_attestation),
        median(|after| &after.register_after_re_attestation),
        m.after_upgrade.as_ref().map_or("-".to_string(), |after| {
            after
                .ops()
                .iter()
                .map(|(_, op)| op.short_status())
                .collect::<Vec<_>>()
                .join(" ")
        }),
    );
}

/// Measures the upgrade from the production binary with the fill already stored, then the
/// victim's registration before and after it reattests under the current contract.
#[tokio::test]
#[ignore = "sandbox benchmark; run explicitly"]
async fn upgrade_from_production__should_migrate_and_keep_victim_registration_working()
-> anyhow::Result<()> {
    print_upgrade_header();
    let mut rows = Vec::new();
    for n in ns_from_env("ATTESTATION_UPGRADE_NS", UPGRADE_NS) {
        // Given
        let env = setup_bench_env(InitialContract::Production).await?;
        env.fill(n).await?;
        env.submit_victim_attestation().await?;

        // When
        let upgrade = env.upgrade_to_current_contract().await?;
        let after_upgrade = if upgrade.error.is_none() {
            let register_stored_before_upgrade = env.register_victim(None).await;
            let re_attestation = env.re_attest_victim(1).await;
            let register_after_re_attestation = env.register_victim(None).await;
            Some(PostUpgradeRegistration {
                register_stored_before_upgrade,
                re_attestation,
                register_after_re_attestation,
            })
        } else {
            None
        };
        let row = UpgradeMeasurement {
            n_attacker_entries: n,
            upgrade,
            after_upgrade,
        };
        print_upgrade_row(&row);
        if let Some(profile) = &row.upgrade.profile {
            println!(
                "  N={n} upgrade receipt profile: {}",
                profile
                    .entries
                    .iter()
                    .take(8)
                    .map(|(cost, gas)| format!("{cost} {}", tgas(Some(*gas))))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        rows.push(row);
    }

    // Then
    for row in &rows {
        let n = row.n_attacker_entries;
        anyhow::ensure!(
            row.upgrade.error.is_none(),
            "upgrade failed at N={n}: {:?}",
            row.upgrade.error
        );
        let after_upgrade = row
            .after_upgrade
            .as_ref()
            .expect("a successful upgrade is followed by the registration runs");
        for (name, op) in after_upgrade.ops() {
            anyhow::ensure!(
                op.error.is_none(),
                "{name} failed at N={n}: {}",
                op.status()
            );
        }
    }
    Ok(())
}
