# TEE Context

The TEE Context is a shared crate (`crates/tee-context`) for the TEE attestation lifecycle. It keeps the contract's TEE state up to date, writes the approved image hashes to disk for the [Launcher][launcher-pattern], and regenerates and submits the service's attestation every hour, so that each service gets these tasks without reimplementing them. The MPC node uses it, and the Backup Service is meant to use it too.

[launcher-pattern]: securing-mpc-with-tee/securing-mpc-with-tee.md#launcher-pattern

## Interface

```rust
/// The TEE state on the contract that an attestation is checked against. Each value is empty
/// until its first successful read.
#[derive(Clone)]
pub struct TeeStateReceivers {
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    pub allowed_os_measurements: watch::Receiver<Vec<ExpectedMeasurements>>,
    /// The attestation the contract stores for the service's TLS public key.
    pub stored_attestation: watch::Receiver<Option<StoredAttestation>>,
}

/// Keeps `TeeStateReceivers` up to date with the contract.
pub struct TeeStateMonitors { .. }

impl TeeStateMonitors {
    pub fn new() -> (Self, TeeStateReceivers);

    /// Spawns one task per contract view. Each task polls its view every second and retries
    /// failed reads forever.
    pub fn spawn<V: ViewContract + Clone + Send + Sync + 'static>(
        self,
        contract: MpcContractHandle<V>,
        tls_public_key: Ed25519PublicKey,
    );
}

/// Writes the allowed image hashes to disk for the Launcher whenever they change. Sends on
/// `shutdown_signal_sender` and returns when a write fails or the receiver closes.
pub async fn monitor_allowed_image_hashes<Storage: AllowedImageHashesStorage + Send + Sync + 'static>(
    cancellation_token: CancellationToken,
    current_image: NodeImageHash,
    allowed_hashes_in_contract: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    image_hash_storage: Storage,
    shutdown_signal_sender: mpsc::Sender<()>,
) -> Result<(), ExitError>;

/// Generates a TDX quote over the given report data; implemented for `TeeAuthority`.
pub trait GenerateAttestation: Send + Sync {
    fn generate_attestation(
        &self,
        report_data: ReportData,
    ) -> impl Future<Output = Result<Attestation, AttestationError>> + Send;
}

/// Sends an attestation for a TLS public key to the contract.
pub trait SubmitAttestation: Clone + Send + Sync {
    /// Succeeds once the transaction is sent. Whether the contract accepted the attestation
    /// shows only in `TeeStateReceivers::stored_attestation`.
    fn submit(
        &self,
        attestation: dtos::Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

pub struct AttestationSubmitter<S, A> {
    pub tee_authority: A,
    pub submitter: S,
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
    pub tee: TeeStateReceivers,
}

/// Regenerates and submits the attestation every hour. Never returns.
pub async fn run_periodic_attestation_submission<S: SubmitAttestation, A: GenerateAttestation>(
    submitter: AttestationSubmitter<S, A>,
);
```

Submission is a port because each service signs with its own key and calls its own contract method. The MPC node implements it by sending `submit_participant_info` through its transaction sender, which holds the only signer of the node's access key: a second signer would keep its own nonce counter and race the node's other transactions.

Each hourly round:

1. Generates an attestation whose report data binds the TLS public key and the account public key.
2. Checks it against the allowed image hashes, launcher compose hashes and OS measurements in `TeeStateReceivers`. A failed check is logged as a warning and the attestation is submitted anyway: the contract runs the authoritative check, and the local view of the allowed lists may be stale.
3. Submits it, retrying with exponential backoff until `stored_attestation` holds an attestation that can be the submitted one. A stored mock attestation does not confirm a submitted Dstack attestation.
4. Abandons a stage still running at the end of the round. The next round starts over with a fresh attestation.

Before each round, it warns if the contract has not accepted an attestation for this TLS public key in the last one and a half rounds.

The attestation lifecycle metrics (`mpc_tee_attestation_*`, `mpc_attestation_*` and `mpc_own_image_hash_*`) are registered by this crate in the default Prometheus registry.

## Usage

The MPC node wires the crate up as follows:

```rust
let (tee_state_monitors, tee) = TeeStateMonitors::new();
tee_state_monitors.spawn(contract, tls_public_key.clone());

tokio::spawn(monitor_allowed_image_hashes(
    cancellation_token.child_token(),
    current_image,
    tee.allowed_image_hashes.clone(),
    AllowedImageHashesFile::from(latest_allowed_hash_file_path),
    image_hash_shutdown_sender,
));

tokio::spawn(run_periodic_attestation_submission(AttestationSubmitter {
    tee_authority,
    submitter: SubmitParticipantInfo(transaction_sender),
    tls_public_key,
    account_public_key,
    tee,
}));
```
