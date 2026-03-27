use std::io::Write;

use clap::Parser;
use launcher_interface::types::{ApprovedHashes, TeeAuthorityConfig, TeeConfig};
use launcher_interface::{DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL, MPC_IMAGE_HASH_EVENT};
use tee_launcher::compose::launch_mpc_container;
use tee_launcher::config::{intercept_node_config, validate_image_name};
use tee_launcher::constants::{
    DSTACK_UNIX_SOCKET, DSTACK_USER_CONFIG_FILE, IMAGE_DIGEST_FILE, MPC_CONFIG_SHARED_PATH,
};
use tee_launcher::error::LauncherError;
use tee_launcher::selection::select_image_hash;
use tee_launcher::types::{CliArgs, Config, Platform};
use tee_launcher::validation::validate_image_hash;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), LauncherError> {
    tracing::info!("start");

    let args = CliArgs::parse();

    tracing::info!(platform = ?args.platform, "starting launcher");

    // Load dstack user config (TOML)
    let config_contents = std::fs::read_to_string(DSTACK_USER_CONFIG_FILE).map_err(|source| {
        LauncherError::FileRead {
            path: DSTACK_USER_CONFIG_FILE.to_string(),
            source,
        }
    })?;

    let config: Config =
        toml::from_str(&config_contents).map_err(|source| LauncherError::TomlParse {
            path: DSTACK_USER_CONFIG_FILE.to_string(),
            source,
        })?;

    validate_image_name(&config.launcher_config.image_name)?;

    let approved_hashes_on_disk: Option<ApprovedHashes> = match std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(IMAGE_DIGEST_FILE)
    {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                ?err,
                default_image_digest = ?args.default_image_digest,
                "approved hashes file does not exist on disk, falling back to default digest"
            );
            None
        }
        Err(err) => {
            return Err(LauncherError::FileRead {
                path: IMAGE_DIGEST_FILE.to_string(),
                source: err,
            });
        }
        Ok(file) => {
            let parsed: ApprovedHashes =
                serde_json::from_reader(file).map_err(|source| LauncherError::JsonParse {
                    path: IMAGE_DIGEST_FILE.to_string(),
                    source,
                })?;
            Some(parsed)
        }
    };

    let image_hash = select_image_hash(
        approved_hashes_on_disk.as_ref(),
        &args.default_image_digest,
        config.launcher_config.mpc_hash_override.as_ref(),
    )?;

    let manifest_digest = validate_image_hash(&config.launcher_config, image_hash.clone()).await?;

    if args.platform == Platform::Tee {
        let dstack_client = dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

        // EmitEvent with the image digest
        dstack_client
            .emit_event(
                MPC_IMAGE_HASH_EVENT.to_string(),
                image_hash.as_ref().to_vec(),
            )
            .await
            .map_err(|e| LauncherError::DstackEmitEventFailed(e.to_string()))?;
    }

    let mpc_binary_config_path = std::path::Path::new(MPC_CONFIG_SHARED_PATH);

    let tee_authority_config = match args.platform {
        Platform::Tee => TeeAuthorityConfig::Dstack {
            dstack_endpoint: DSTACK_UNIX_SOCKET.to_string(),
            quote_upload_url: DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL.to_string(),
        },
        Platform::NonTee => TeeAuthorityConfig::Local,
    };

    let tee_config = TeeConfig {
        authority: tee_authority_config,
        image_hash: image_hash.clone(),
        latest_allowed_hash_file_path: IMAGE_DIGEST_FILE
            .parse()
            .expect("image digest file has a valid path"),
    };

    let mpc_node_config = intercept_node_config(config.mpc_node_config, &tee_config)?;

    let mpc_config_toml =
        toml::to_string(&mpc_node_config).expect("re-serializing a toml::Table always succeeds");

    // Write config atomically (temp file + rename) to avoid partial writes on crash.
    let config_dir = mpc_binary_config_path
        .parent()
        .unwrap_or(std::path::Path::new("/"));
    let mut tmp =
        tempfile::NamedTempFile::new_in(config_dir).map_err(LauncherError::TempFileCreate)?;
    tmp.write_all(mpc_config_toml.as_bytes())
        .map_err(|source| LauncherError::FileWrite {
            path: mpc_binary_config_path.display().to_string(),
            source,
        })?;
    tmp.persist(mpc_binary_config_path)
        .map_err(|e| LauncherError::FileWrite {
            path: e.file.path().display().to_string(),
            source: e.error,
        })?;

    launch_mpc_container(
        args.platform,
        &manifest_digest,
        &config.launcher_config.image_name,
        &config.launcher_config.port_mappings,
    )?;

    Ok(())
}
