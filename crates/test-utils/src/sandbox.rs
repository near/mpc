use std::ops::Deref;
use std::sync::Arc;

use near_workspaces::Worker;
use near_workspaces::network::{Sandbox, ValidatorKey};

/// How many epochs the sandbox retains before garbage-collecting old blocks.
///
/// `near-sandbox init --fast` produces 60-block epochs, and neard's default
/// `gc_num_epochs_to_keep = 5` leaves a retention window of only ~245–300
/// blocks. A test that submits many transactions and polls their outcomes at
/// the end (e.g. `respond__should_drain_saturated_fan_out_queue`, spanning
/// ~600 blocks) loses the earliest outcomes to GC and fails with unknown-
/// transaction errors (see issue #4461). 20 epochs guarantee a window of at
/// least 19 × 60 = 1140 blocks.
const GC_NUM_EPOCHS_TO_KEEP: u32 = 20;

/// A [`Worker`] connected to a sandbox instance owned by this handle.
///
/// The sandbox is started through the [`near_sandbox`] crate directly instead
/// of [`near_workspaces::sandbox_with_version`], because near-workspaces does
/// not expose the node-config overrides we need (block retention, see
/// [`GC_NUM_EPOCHS_TO_KEEP`]). The handle derefs to the inner [`Worker`];
/// dropping the last clone kills the sandbox process, exactly like a worker
/// obtained from near-workspaces.
#[derive(Clone)]
pub struct SandboxWorker {
    worker: Worker<Sandbox>,
    _sandbox: Arc<near_sandbox::Sandbox>,
}

impl Deref for SandboxWorker {
    type Target = Worker<Sandbox>;

    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}

/// Starts a [`crate::DEFAULT_SANDBOX_VERSION`] sandbox with an extended block
/// retention window and attaches a [`Worker`] to it.
pub async fn start_sandbox() -> anyhow::Result<SandboxWorker> {
    let config = near_sandbox::SandboxConfig {
        // near-workspaces adds this account itself when it spawns the sandbox;
        // top-level account creation (`dev_create_account` etc.) needs it.
        additional_accounts: vec![near_sandbox::GenesisAccount::default_with_name(
            "registrar".parse().expect("static account id is valid"),
        )],
        additional_config: Some(serde_json::json!({
            "gc_num_epochs_to_keep": GC_NUM_EPOCHS_TO_KEEP,
        })),
        ..Default::default()
    };
    let sandbox = near_sandbox::Sandbox::start_sandbox_with_config_and_version(
        config,
        crate::DEFAULT_SANDBOX_VERSION,
    )
    .await?;
    let worker = near_workspaces::sandbox()
        .rpc_addr(&sandbox.rpc_addr)
        .validator_key(ValidatorKey::HomeDir(sandbox.home_dir.path().to_path_buf()))
        .await?;
    Ok(SandboxWorker {
        worker,
        _sandbox: Arc::new(sandbox),
    })
}
