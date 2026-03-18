use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Attestation, DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey, MockAttestation,
    Participants, ProtocolContractState, SignatureScheme, Threshold, ThresholdParameters,
};
use near_workspaces::network::Custom;
use near_workspaces::types::{AccessKey, Gas, NearToken};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;

use crate::sandbox::SandboxNode;

const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(15);
const GAS_FOR_CKD_CALL: Gas = Gas::from_tgas(15);
const SIGNATURE_DEPOSIT: u128 = 1;
const CKD_DEPOSIT: u128 = 1;

/// Pure RPC client for interacting with the NEAR blockchain.
///
/// Wraps `near-workspaces::Worker<Custom>` to provide contract deployment,
/// account management, and MPC contract interactions. Environment-agnostic:
/// can target sandbox or testnet.
pub struct NearBlockchain {
    worker: Worker<Custom>,
    root_account: Account,
    contract: Option<Contract>,
    user_account: Option<Account>,
}

impl NearBlockchain {
    /// Connect to an existing sandbox node via RPC.
    ///
    /// Reads the validator key from the sandbox home directory to obtain the
    /// root account (`test.near`) credentials.
    pub async fn from_sandbox(sandbox: &SandboxNode) -> anyhow::Result<Self> {
        let rpc_url = sandbox.rpc_url();
        tracing::info!(%rpc_url, "connecting near-workspaces to sandbox");

        let worker = near_workspaces::custom(&rpc_url)
            .await
            .context("failed to connect near-workspaces to sandbox")?;

        // Load the validator key to get root account credentials.
        let validator_key_path = sandbox.home_dir().join("validator_key.json");
        let (account_id, secret_key) = load_key_file(&validator_key_path)?;

        let root_account = Account::from_secret_key(account_id, secret_key, &worker);

        Ok(Self {
            worker,
            root_account,
            contract: None,
            user_account: None,
        })
    }

    /// Deploy the MPC contract WASM and set up a user account for requests.
    pub async fn deploy_contract(&mut self, wasm: &[u8]) -> anyhow::Result<()> {
        // Deploy to a subaccount of root
        let contract_account_id: AccountId = format!("mpc.{}", self.root_account.id())
            .parse()
            .context("invalid contract account id")?;

        let (_, sk) = self.worker.generate_dev_account_credentials();
        let result = self
            .root_account
            .batch(&contract_account_id)
            .create_account()
            .add_key(sk.public_key(), AccessKey::full_access())
            .transfer(NearToken::from_near(100))
            .deploy(wasm)
            .transact()
            .await
            .context("failed to deploy contract")?;

        anyhow::ensure!(
            result.is_success(),
            "contract deployment failed: {result:?}"
        );

        let contract = Contract::from_secret_key(contract_account_id, sk, &self.worker);
        self.contract = Some(contract);

        // Create a user account for submitting sign/ckd requests
        let user_account_id: AccountId = format!("user.{}", self.root_account.id())
            .parse()
            .context("invalid user account id")?;

        let (_, user_sk) = self.worker.generate_dev_account_credentials();
        let result = self
            .root_account
            .batch(&user_account_id)
            .create_account()
            .add_key(user_sk.public_key(), AccessKey::full_access())
            .transfer(NearToken::from_near(100))
            .transact()
            .await
            .context("failed to create user account")?;

        anyhow::ensure!(
            result.is_success(),
            "user account creation failed: {result:?}"
        );

        self.user_account = Some(Account::from_secret_key(
            user_account_id,
            user_sk,
            &self.worker,
        ));
        Ok(())
    }

    pub fn contract(&self) -> &Contract {
        self.contract.as_ref().expect("contract not deployed")
    }

    pub fn contract_id(&self) -> &AccountId {
        self.contract().id()
    }

    pub fn user_account(&self) -> &Account {
        self.user_account
            .as_ref()
            .expect("user account not created")
    }

    pub fn root_account(&self) -> &Account {
        &self.root_account
    }

    pub fn worker(&self) -> &Worker<Custom> {
        &self.worker
    }

    /// Create a named subaccount under root (e.g. `signer_0.test.near`).
    pub async fn create_subaccount(&self, name: &str) -> anyhow::Result<Account> {
        let account_id: AccountId = format!("{name}.{}", self.root_account.id())
            .parse()
            .with_context(|| format!("invalid subaccount id: {name}"))?;

        let (_, sk) = self.worker.generate_dev_account_credentials();
        let result = self
            .root_account
            .batch(&account_id)
            .create_account()
            .add_key(sk.public_key(), AccessKey::full_access())
            .transfer(NearToken::from_near(100))
            .transact()
            .await
            .with_context(|| format!("failed to create subaccount {name}"))?;

        anyhow::ensure!(
            result.is_success(),
            "subaccount creation failed: {result:?}"
        );

        Ok(Account::from_secret_key(account_id, sk, &self.worker))
    }

    /// Initialize the MPC contract with threshold parameters.
    pub async fn init_contract(&self, params: &ThresholdParameters) -> anyhow::Result<()> {
        let contract = self.contract();
        let result = contract
            .call(method_names::INIT)
            .args_json(json!({
                "parameters": params,
            }))
            .max_gas()
            .transact()
            .await
            .context("init call failed")?;

        anyhow::ensure!(result.is_success(), "init failed: {result:?}");
        Ok(())
    }

    /// Submit mock TEE attestation for a participant.
    pub async fn submit_attestation(&self, account: &Account, sign_pk: &str) -> anyhow::Result<()> {
        let attestation = Attestation::Mock(MockAttestation::Valid);
        let tls_key: Ed25519PublicKey = sign_pk
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ed25519 public key: {e}"))?;

        let result = account
            .call(self.contract_id(), method_names::SUBMIT_PARTICIPANT_INFO)
            .args_json((&attestation, &tls_key))
            .max_gas()
            .transact()
            .await
            .context("submit_participant_info failed")?;

        anyhow::ensure!(
            result.is_success(),
            "submit_participant_info failed: {result:?}"
        );
        Ok(())
    }

    /// Vote to add domains from each voter account.
    pub async fn vote_add_domains(
        &self,
        voters: &[&Account],
        domains: &[DomainConfig],
    ) -> anyhow::Result<()> {
        let args = json!({ "domains": domains });

        for voter in voters {
            let result = voter
                .call(self.contract_id(), method_names::VOTE_ADD_DOMAINS)
                .args_json(&args)
                .max_gas()
                .transact()
                .await
                .with_context(|| format!("vote_add_domains failed for {}", voter.id()))?;

            anyhow::ensure!(
                result.is_success(),
                "vote_add_domains failed for {}: {result:?}",
                voter.id()
            );
        }
        Ok(())
    }

    /// Query the contract state view.
    pub async fn get_state(&self) -> anyhow::Result<ProtocolContractState> {
        let result = self
            .contract()
            .view(method_names::STATE)
            .await
            .context("state view failed")?;

        result
            .json()
            .context("failed to deserialize contract state")
    }

    /// Wait until the contract reaches the Running state.
    pub async fn wait_for_running(&self, timeout: Duration) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            let state = self.get_state().await?;
            match &state {
                ProtocolContractState::Running(_) => {
                    tracing::info!("contract is in Running state");
                    return Ok(());
                }
                _ => {
                    if start.elapsed() > timeout {
                        anyhow::bail!(
                            "timed out waiting for Running state after {:?}, current: {state:?}",
                            timeout
                        );
                    }
                    tracing::debug!(?state, "waiting for Running state...");
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    /// Wait until the contract reaches the Initializing state.
    pub async fn wait_for_initializing(&self, timeout: Duration) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            let state = self.get_state().await?;
            match &state {
                ProtocolContractState::Initializing(_) => {
                    tracing::info!("contract is in Initializing state");
                    return Ok(());
                }
                _ => {
                    if start.elapsed() > timeout {
                        anyhow::bail!(
                            "timed out waiting for Initializing state after {:?}, current: {state:?}",
                            timeout
                        );
                    }
                    tracing::debug!(?state, "waiting for Initializing state...");
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    /// Submit signature requests for all Sign domains and wait for responses.
    pub async fn send_and_await_signature_requests(
        &self,
        num_per_domain: usize,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let state = self.get_state().await?;
        let ProtocolContractState::Running(running) = state else {
            anyhow::bail!("contract not in Running state");
        };

        let user = self.user_account();
        let contract_id = self.contract_id().clone();

        for domain in &running.domains.domains {
            let purpose = domain.purpose.as_ref();
            let is_sign = matches!(purpose, Some(DomainPurpose::Sign) | None);
            let is_ecdsa_or_eddsa = matches!(
                domain.scheme,
                SignatureScheme::Secp256k1 | SignatureScheme::Ed25519
            );

            if !is_sign || !is_ecdsa_or_eddsa {
                continue;
            }

            tracing::info!(
                domain_id = domain.id.0,
                scheme = ?domain.scheme,
                count = num_per_domain,
                "submitting sign requests"
            );

            for i in 0..num_per_domain {
                let payload = match domain.scheme {
                    SignatureScheme::Secp256k1 => {
                        let bytes: [u8; 32] = rand::random();
                        json!({"Ecdsa": hex::encode(bytes)})
                    }
                    SignatureScheme::Ed25519 => {
                        let bytes: [u8; 32] = rand::random();
                        json!({"Eddsa": hex::encode(bytes)})
                    }
                    _ => continue,
                };

                let args = json!({
                    "request": {
                        "domain_id": domain.id.0,
                        "path": "test",
                        "payload_v2": payload,
                    }
                });

                let start = tokio::time::Instant::now();
                loop {
                    let result = user
                        .call(&contract_id, method_names::SIGN)
                        .args_json(&args)
                        .gas(GAS_FOR_SIGN_CALL)
                        .deposit(NearToken::from_yoctonear(SIGNATURE_DEPOSIT))
                        .transact()
                        .await
                        .with_context(|| {
                            format!("sign request {i} for domain {} failed", domain.id.0)
                        })?;

                    if result.is_success() {
                        tracing::info!(
                            domain_id = domain.id.0,
                            request = i,
                            "sign request succeeded"
                        );
                        break;
                    }

                    if start.elapsed() > timeout {
                        anyhow::bail!(
                            "sign request {i} for domain {} timed out: {result:?}",
                            domain.id.0
                        );
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Ok(())
    }

    /// Submit CKD requests for all CKD domains and wait for responses.
    pub async fn send_and_await_ckd_requests(
        &self,
        num_per_domain: usize,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let state = self.get_state().await?;
        let ProtocolContractState::Running(running) = state else {
            anyhow::bail!("contract not in Running state");
        };

        let user = self.user_account();
        let contract_id = self.contract_id().clone();

        for domain in &running.domains.domains {
            let purpose = domain.purpose.as_ref();
            if !matches!(purpose, Some(DomainPurpose::CKD)) {
                continue;
            }

            tracing::info!(
                domain_id = domain.id.0,
                scheme = ?domain.scheme,
                count = num_per_domain,
                "submitting CKD requests"
            );

            for i in 0..num_per_domain {
                // BLS12-381 G1 generator point (compressed, 48 bytes).
                // This is a well-known valid point on the curve.
                let bls_g1_generator: [u8; 48] = [
                    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c,
                    0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
                    0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f,
                    0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
                ];
                let app_public_key =
                    format!("bls12381g1:{}", bs58::encode(&bls_g1_generator).into_string());

                let args = json!({
                    "request": {
                        "derivation_path": format!("test/{i}"),
                        "app_public_key": app_public_key,
                        "domain_id": domain.id.0,
                    }
                });

                let start = tokio::time::Instant::now();
                loop {
                    let result = user
                        .call(&contract_id, method_names::REQUEST_APP_PRIVATE_KEY)
                        .args_json(&args)
                        .max_gas()
                        .deposit(NearToken::from_yoctonear(CKD_DEPOSIT))
                        .transact()
                        .await
                        .with_context(|| {
                            format!("CKD request {i} for domain {} failed", domain.id.0)
                        })?;

                    if result.is_success() {
                        tracing::info!(
                            domain_id = domain.id.0,
                            request = i,
                            "CKD request succeeded"
                        );
                        break;
                    }

                    if start.elapsed() > timeout {
                        anyhow::bail!(
                            "CKD request {i} for domain {} timed out: {result:?}",
                            domain.id.0
                        );
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Ok(())
    }
}

/// Build ThresholdParameters from participant data.
pub fn make_threshold_parameters(
    accounts: &[(AccountId, String)], // (account_id, sign_pk)
    p2p_urls: &[String],
    threshold: u64,
) -> ThresholdParameters {
    let mut participants_list = Vec::new();
    for (i, ((account_id, sign_pk), url)) in accounts.iter().zip(p2p_urls.iter()).enumerate() {
        participants_list.push((
            near_mpc_contract_interface::types::AccountId(account_id.to_string()),
            near_mpc_contract_interface::types::ParticipantId(i as u32),
            near_mpc_contract_interface::types::ParticipantInfo {
                url: url.clone(),
                sign_pk: sign_pk.clone(),
            },
        ));
    }

    ThresholdParameters {
        participants: Participants {
            next_id: near_mpc_contract_interface::types::ParticipantId(accounts.len() as u32),
            participants: participants_list,
        },
        threshold: Threshold(threshold),
    }
}

/// Build the default set of domains to add: Secp256k1/Sign, Ed25519/Sign, Bls12381/CKD.
pub fn default_domains(start_id: u64) -> Vec<DomainConfig> {
    vec![
        DomainConfig {
            id: DomainId(start_id),
            scheme: SignatureScheme::Secp256k1,
            purpose: Some(DomainPurpose::Sign),
        },
        DomainConfig {
            id: DomainId(start_id + 1),
            scheme: SignatureScheme::Ed25519,
            purpose: Some(DomainPurpose::Sign),
        },
        DomainConfig {
            id: DomainId(start_id + 2),
            scheme: SignatureScheme::Bls12381,
            purpose: Some(DomainPurpose::CKD),
        },
    ]
}

/// Load account id and secret key from a NEAR key file (validator_key.json format).
fn load_key_file(path: &Path) -> anyhow::Result<(AccountId, near_workspaces::types::SecretKey)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key file: {}", path.display()))?;

    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("failed to parse key file")?;

    let account_id: AccountId = parsed["account_id"]
        .as_str()
        .context("missing account_id")?
        .parse()
        .context("invalid account_id")?;

    let secret_key: near_workspaces::types::SecretKey = parsed["secret_key"]
        .as_str()
        .context("missing secret_key")?
        .parse()
        .context("invalid secret_key")?;

    Ok((account_id, secret_key))
}
