# TEE Context

The TEE Context is a shared crate for the TEE attestation lifecycle. It polls governance contract state (allowed image hashes) and exposes methods for attestation submission and verification — so that each service gets these capabilities without reimplementing contract interactions. Each service is responsible for its own attestation scheduling (when to submit, when to call `verify_tee`). The MPC node already implements these operations today; they will be extracted into a standalone crate reusable by all services. The MPC node depends on both the MPC Context (for protocol orchestration) and the TEE Context (for attestation) as separate, parallel components. Other services (Archive Signer, Backup Service) use the TEE Context directly.

## Interface

```rust
/// Allowed TEE hashes fetched from the governance contract.
pub struct AllowedTeeHashes {
    pub allowed_docker_image_hashes: Vec<MpcDockerImageHash>,
    pub allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
}

/// Identity of this node within the TEE network.
pub struct TeeNodeIdentity {
    pub node_account_id: AccountId,
    pub account_public_key: Ed25519PublicKey,
}

/// The background task spawned by `new()` owns the `ContractMethodSubscription`
/// (not `Clone` — holds `JoinHandle`) and sends updates via a `watch` channel.
#[derive(Clone)]
pub struct TeeContext {
    node_identity: TeeNodeIdentity,
    governance_contract: AccountId,
    allowed_hashes_tx: watch::Sender<AllowedTeeHashes>,
    transaction_sender: TransactionSender,
}

impl TeeContext {
    /// Creates a new `TeeContext`. Spawns a background task that owns the
    /// `ContractMethodSubscription`, polls the governance contract, and
    /// sends updates via a `watch` channel. Waits for the first successful
    /// poll before returning.
    pub async fn new(
        viewer: impl ViewRaw,
        node_identity: TeeNodeIdentity,
        // e.g. v1.signer (MPC node) or the HOT governance contract (Archive Signer).
        governance_contract: AccountId,
        transaction_sender: TransactionSender,
    ) -> Result<Self, Error> {
        // `ContractMethodSubscription` is not `Clone` (holds `JoinHandle`),
        // so it stays inside the background task.
        let mut subscription = ContractMethodSubscription::<AllowedTeeHashes>::new(
            viewer,
            governance_contract.clone(),
            "allowed_docker_image_hashes",
            b"{}".to_vec(),
        ).await;

        // First value is already available after construction.
        let initial = subscription.latest()?.value;
        let (allowed_hashes_tx, _) = watch::channel(initial);

        // Background task: owns the subscription, sends updates.
        tokio::spawn({
            let allowed_hashes_tx = allowed_hashes_tx.clone();
            async move {
                loop {
                    subscription.changed().await?;
                    let new_hashes = subscription.latest()?.value;
                    allowed_hashes_tx.send_replace(new_hashes);
                }
            }
        });

        Ok(Self {
            node_identity,
            governance_contract,
            allowed_hashes_tx,
            transaction_sender,
        })
    }

    /// Returns a `watch::Receiver` for the allowed TEE hashes.
    /// Use `.borrow()` to read the latest value, `.changed()` to wait for updates.
    pub fn watch_allowed_tee_hashes(&self) -> watch::Receiver<AllowedTeeHashes>;

    /// Submits an attestation to the governance contract via
    /// submit_participant_info(). The caller builds its own ReportData
    /// (e.g. the MPC node includes its TLS public key, the Archive Signer
    /// does not) and generates the attestation quote via tee-authority.
    /// TeeContext just submits it.
    pub async fn submit_attestation(&self, attestation: Attestation) -> Result<(), Error>;

    /// Calls verify_tee() on the governance contract, triggering on-chain
    /// re-validation of all stored attestations. The caller is responsible
    /// for scheduling (e.g., every 2 days).
    pub async fn verify_tee(&self) -> Result<(), Error>;
}
```

Callers subscribe to allowed hashes via `watch_allowed_tee_hashes()`, which returns a `watch::Receiver`. The background task polls the Chain Gateway and pushes updates through the channel. The TEE Context does not write to disk — persistence is the caller's responsibility.

`ReportData` is versioned per service — each service defines what goes into its attestation quote. For example, the MPC node includes its TLS public key in `ReportData` (needed for P2P connections), while the Archive Signer does not. This keeps services decoupled: changes to the MPC node's `ReportData` format do not require changes in other services.

Each service passes its governance contract address to `TeeContext::new()`. All governance contracts expose the same attestation-related methods (see [Attestation Methods][tee-context-methods]) since they share [`TeeState`][tee-state]. Voting methods vary per contract.

[tee-context-methods]: tee-lifecycle.md#attestation-methods

[tee-state]: https://github.com/near/mpc/blob/ce53324f472aa89fdf702d7482211bbdb6a44967/crates/contract/src/tee/tee_state.rs#L92

### Usage

Every TEE service follows the same pattern: start the TEE Context, spawn a watcher loop to write hashes to disk for the [Launcher][launcher-pattern], and periodically re-submit attestations.

[archive-signer]: hot-tee-signing-design.md
[launcher-pattern]: securing-mpc-with-tee-design-doc.md#launcher-pattern

```rust
let tee_ctx = TeeContext::new(viewer, node_identity, governance_contract, transaction_sender).await?;

// Write hashes to disk for the Launcher whenever they change.
let mut hashes_rx = tee_ctx.watch_allowed_tee_hashes();
tokio::spawn(async move {
    loop {
        hashes_rx.changed().await?;
        let hashes = hashes_rx.borrow().clone();
        write_hashes_to_disk(&hashes.allowed_docker_image_hashes).await?;
    }
});

// Periodic attestation submission (every 7 days).
tokio::spawn({
    let tee_ctx = tee_ctx.clone();
    async move {
        loop {
            let quote = tee_authority.generate_quote(&report_data)?;
            tee_ctx.submit_attestation(quote).await?;
            tokio::time::sleep(Duration::from_secs(7 * 24 * 3600)).await;
        }
    }
});
```
