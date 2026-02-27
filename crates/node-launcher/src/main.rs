mod config;
mod docker_cmd;
mod registry;
mod rtmr;

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

fn main() {
    init_logging();

    if let Err(e) = run() {
        tracing::error!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
}

fn run() -> anyhow::Result<()> {
    tracing::info!("MPC TEE Launcher starting");

    // 1. Parse platform from process env (never from user_config)
    let platform = config::parse_platform().context("failed to parse platform")?;
    tracing::info!("Launcher platform: {platform:?}");

    // 2. TEE mode: verify dstack socket exists early (fail-closed)
    if platform == config::Platform::Tee {
        rtmr::verify_unix_socket(docker_cmd::DSTACK_UNIX_SOCKET)
            .context("TEE platform requires dstack unix socket")?;
    }

    // 3. Verify DOCKER_CONTENT_TRUST=1
    let dct = std::env::var("DOCKER_CONTENT_TRUST").unwrap_or_default();
    if dct != "1" {
        bail!("Environment variable DOCKER_CONTENT_TRUST must be set to 1.");
    }

    // 4. Load dstack user config
    // In dstack, /tapp/user_config provides unmeasured data to the CVM.
    // Only security-irrelevant parts may be configurable this way.
    let user_config = config::load_user_config(Path::new(config::DSTACK_USER_CONFIG_FILE))
        .context("failed to load user config")?;

    // 5. Load RPC timing config
    let rpc_timing = config::load_rpc_timing_config(&user_config);

    // 6. Select approved hash (override or newest)
    let selected_hash =
        config::load_and_select_hash(&user_config).context("failed to select image hash")?;
    tracing::info!("Selected MPC image hash: {}", selected_hash.full());

    // 7. Validate image hash against Docker registry
    let image_spec = config::get_image_spec(&user_config);
    let resolved = config::ResolvedImage {
        spec: image_spec,
        digest: selected_hash.clone(),
    };
    registry::validate_image_hash(&resolved, &rpc_timing)
        .context("MPC image hash validation failed")?;
    tracing::info!(
        "MPC image hash validated successfully: {}",
        selected_hash.full()
    );

    // 8. Extend RTMR3 (no-op for NonTee)
    rtmr::extend_rtmr3(platform, &selected_hash).context("failed to extend RTMR3")?;

    // 9. Launch MPC container
    docker_cmd::remove_existing_container();
    let cmd = docker_cmd::build_docker_cmd(platform, &user_config, &selected_hash)
        .context("failed to build docker command")?;

    tracing::info!("Launching MPC container");
    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .context("failed to execute docker run")?;

    if !status.success() {
        bail!("docker run failed with exit code: {:?}", status.code());
    }

    tracing::info!("MPC launched successfully");
    Ok(())
}
