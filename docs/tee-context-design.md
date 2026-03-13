# TEE Context

The TEE Context is a shared crate for the TEE attestation lifecycle. It polls governance contract state (allowed image hashes) and exposes methods for attestation submission and verification — so that each service gets these capabilities without reimplementing contract interactions. Each service is responsible for its own attestation scheduling (when to submit, when to call `verify_tee`). The MPC node already implements these operations today; they will be extracted into a standalone crate reusable by all services. In the MPC node, the [MPC Context][mpc-context] depends on the TEE Context for attestation and adds MPC-specific orchestration on top. Other services (Archive Signer, Backup Service) use the TEE Context directly.

[mpc-context]: indexer-design.md

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
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
}

impl TeeContext {
    /// Subscribes to the governance contract's view methods via
    /// StreamContractState and waits for the first successful poll before
    /// returning. After construction, allowed_tee_hashes() is guaranteed
    /// to return data.
    pub async fn new(
        chain_gateway: ChainGateway,
        node_identity: TeeNodeIdentity,
        // e.g. v1.signer (MPC node) or the HOT governance contract (Archive Signer).
        governance_contract: AccountId,
    ) -> Result<Self, Error>;

    /// Returns the latest allowed TEE hashes.
    /// Delegates to StreamContractState::latest().
    pub fn allowed_tee_hashes(&self) -> Result<AllowedTeeHashes, Error>;

    /// Resolves when the allowed TEE hashes change.
    /// Delegates to StreamContractState::changed().
    pub async fn allowed_tee_hashes_changed(&self) -> Result<(), Error>;

    /// Submits an attestation to the governance contract via
    /// submit_participant_info(). The caller is responsible for generating
    /// the attestation quote (via tee-authority) and deciding when to submit.
    pub async fn submit_attestation(&self, attestation: Attestation) -> Result<(), Error>;

    /// Calls verify_tee() on the governance contract, triggering on-chain
    /// re-validation of all stored attestations. The caller is responsible
    /// for scheduling (e.g., every 2 days).
    pub async fn verify_tee(&self) -> Result<(), Error>;
}
```

The read methods (`allowed_tee_hashes`) and their `_changed()` counterparts delegate to the Chain Gateway, which handles background polling internally. The TEE Context does not write to disk — persistence is the caller's responsibility.

Each service passes its governance contract address to `TeeContext::new()`. All governance contracts expose the same attestation-related methods (see [Attestation Methods][tee-context-methods]) since they share [`TeeState`][tee-state]. Voting methods vary per contract.

[tee-context-methods]: tee-lifecycle.md#attestation-methods

[tee-state]: https://github.com/near/mpc/blob/ce53324f472aa89fdf702d7482211bbdb6a44967/crates/contract/src/tee/tee_state.rs#L92

### Usage: MPC Node

The MPC node wraps the TEE Context inside the [MPC Context][mpc-context]. It manages its own attestation lifecycle — periodic submission, removal monitoring, and `verify_tee` scheduling:

```rust
let tee_ctx = TeeContext::new(chain_gateway, node_identity, governance_contract).await?;

// Write hashes to disk for the Launcher whenever they change.
tokio::spawn({
    let tee_ctx = tee_ctx.clone();
    async move {
        loop {
            tee_ctx.allowed_tee_hashes_changed().await?;
            let hashes = tee_ctx.allowed_tee_hashes()?;
            write_hashes_to_disk(&hashes.allowed_docker_image_hashes).await?;
        }
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

### Usage: Archive Signer

The [Archive Signer][archive-signer] uses the TEE Context directly. Since `new()` waits for the first poll, the image hash check at boot is straightforward:

[archive-signer]: hot-tee-signing-design.md

```rust
let tee_ctx = TeeContext::new(chain_gateway, node_identity, governance_contract).await?;
let hashes = tee_ctx.allowed_tee_hashes()?;
if !hashes.allowed_docker_image_hashes.contains(&current_image) {
    bail!("image not approved");
}

// Submit initial attestation, then schedule periodic re-submission.
let quote = tee_authority.generate_quote(&report_data)?;
tee_ctx.submit_attestation(quote).await?;

start_http_server(tee_ctx).await?;
```
