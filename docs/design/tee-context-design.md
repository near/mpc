# TEE Context

The TEE Context is a shared crate (`crates/tee-context`) for the TEE attestation lifecycle. It polls governance contract state (allowed image hashes) and exposes methods for attestation submission and verification — so that each service gets these capabilities without reimplementing contract interactions. Each service is responsible for its own attestation scheduling (when to submit, when to call `verify_tee`). The MPC node depends on both the MPC Context (for protocol orchestration) and the TEE Context (for attestation) as separate, parallel components. Other services (Archive Signer, Backup Service) use the TEE Context directly.

## Interface

```rust
/// Allowed TEE hashes fetched from the governance contract.
pub struct AllowedTeeHashes {
    pub allowed_docker_image_hashes: Vec<AllowedMpcDockerImageHash>,
    pub allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
}

/// Generic over the chain backend: `S` is any `ViewContract` +
/// `SubmitFunctionCall` + `HasPollInterval` (the chain gateway in
/// production, a mock in tests).
pub struct TeeContext<S> { .. }

impl<S> TeeContext<S> {
    /// Subscribes to the governance contract's allowed image and launcher
    /// hash view methods, waits for the first successful poll of each, then
    /// spawns a background task that merges updates into a single
    /// `AllowedTeeHashes` watch channel. The task is cancelled when the
    /// `TeeContext` is dropped.
    pub async fn new(
        chain_gateway: S,
        // e.g. v1.signer (MPC node) or the HOT governance contract (Archive Signer).
        governance_contract: AccountId,
        signer: TransactionSigner,
    ) -> Result<Self, TeeContextError>;

    /// Returns a `watch::Receiver` for the allowed TEE hashes.
    /// Use `.borrow()` to read the latest value, `.changed()` to wait for updates.
    pub fn watch_allowed_tee_hashes(&self) -> watch::Receiver<AllowedTeeHashes>;

    /// Submits an attestation to the governance contract via
    /// submit_participant_info(). The caller generates the attestation
    /// quote via tee-authority; TeeContext just submits it.
    pub async fn submit_attestation(
        &self,
        attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> Result<(), TeeContextError>;

    /// Calls verify_tee() on the governance contract, triggering on-chain
    /// re-validation of all stored attestations. The caller is responsible
    /// for scheduling (e.g., every 2 days).
    pub async fn verify_tee(&self) -> Result<(), TeeContextError>;
}
```

Callers subscribe to allowed hashes via `watch_allowed_tee_hashes()`, which returns a `watch::Receiver`. The background task polls the Chain Gateway and pushes updates through the channel. The TEE Context does not write to disk — persistence is the caller's responsibility.

`ReportData` is versioned per service — each service defines what goes into its attestation quote. For example, the MPC node includes its TLS public key in `ReportData` (needed for P2P connections), while the Archive Signer does not. This keeps services decoupled: changes to the MPC node's `ReportData` format do not require changes in other services.

Each service passes its governance contract address to `TeeContext::new()`. All governance contracts expose the same attestation-related methods (see [Attestation Methods][tee-context-methods]) since they share [`TeeState`][tee-state]. Voting methods vary per contract.

[tee-context-methods]: tee-lifecycle.md#attestation-methods

[tee-state]: https://github.com/near/mpc/blob/ce53324f472aa89fdf702d7482211bbdb6a44967/crates/contract/src/tee/tee_state.rs#L92

### Usage

Every TEE service follows the same pattern: start the TEE Context, spawn a watcher loop to write hashes to disk for the [Launcher][launcher-pattern], and periodically re-submit attestations.

[archive-signer]: ../archive/design/hot-tee-signing-design.md
[launcher-pattern]: securing-mpc-with-tee/securing-mpc-with-tee.md#launcher-pattern

```rust
let tee_ctx = TeeContext::new(chain_gateway, governance_contract, signer).await?;

// Write hashes to disk for the Launcher whenever they change.
let mut hashes_rx = tee_ctx.watch_allowed_tee_hashes();
tokio::spawn(async move {
    while hashes_rx.changed().await.is_ok() {
        let hashes = hashes_rx.borrow().clone();
        if let Err(error) = write_hashes_to_disk(&hashes.allowed_docker_image_hashes).await {
            tracing::error!(%error, "writing the allowed hashes to disk failed");
        }
    }
});

// Periodic attestation submission (every hour); failures are logged and retried on the
// next interval, so the task never dies.
tokio::spawn({
    let tee_ctx = tee_ctx.clone();
    async move {
        loop {
            let submission = async {
                let quote = tee_authority.generate_quote(&report_data)?;
                tee_ctx.submit_attestation(quote).await
            };
            if let Err(error) = submission.await {
                tracing::error!(%error, "attestation submission failed");
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
});
```
