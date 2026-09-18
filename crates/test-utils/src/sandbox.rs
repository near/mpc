use std::ops::Deref;
use std::sync::Arc;

use near_workspaces::Worker;
use near_workspaces::network::{Sandbox, ValidatorKey};

/// The neard default of 5 epochs (~300 blocks at the sandbox's 60-block
/// epochs) is outlived by `respond__should_drain_saturated_fan_out_queue`,
/// which spans ~600 blocks before polling its earliest tx outcomes — GC drops
/// them first (#4461). 20 epochs retain at least 19 × 60 = 1140 blocks.
const GC_NUM_EPOCHS_TO_KEEP: u32 = 20;

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

/// Starts the sandbox through [`near_sandbox`] directly because
/// [`near_workspaces::sandbox_with_version`] does not expose the node-config
/// overrides we need (block retention).
pub async fn start_sandbox() -> anyhow::Result<SandboxWorker> {
    let config = near_sandbox::SandboxConfig {
        // near-workspaces adds this account when it spawns the sandbox itself;
        // top-level account creation needs it.
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
