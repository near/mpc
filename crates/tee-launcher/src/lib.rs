use std::io::Write;
use std::path::Path;

use clap::Parser;
use launcher_interface::MPC_IMAGE_HASH_EVENT;
use launcher_interface::types::{
    ApprovedHashes, DockerSha256Digest, TeeAuthorityConfig, TeeConfig,
};

use compose::launch_mpc_container;
use config::{intercept_node_config, validate_image_reference};
use constants::{
    DSTACK_UNIX_SOCKET, DSTACK_USER_CONFIG_FILE, IMAGE_DIGEST_FILE, MPC_CONFIG_SHARED_PATH,
};
use error::LauncherError;
use selection::select_image_hash;
use types::{CliArgs, Config, Platform};
use validation::pull_with_retry;

pub mod compose;
pub mod config;
pub mod constants;
pub mod error;
pub mod selection;
pub mod types;
pub mod validation;

pub async fn run() -> Result<(), LauncherError> {
    tracing::info!("start");

    let args = CliArgs::parse();

    tracing::info!(platform = ?args.platform, "starting launcher");

    let config = load_config()?;

    let approved_hashes_on_disk = load_approved_hashes(&args.default_image_digest)?;

    // The approved hashes file now contains manifest digests.
    // We can pull directly by digest without querying the Docker registry API.
    let manifest_digest = select_image_hash(
        approved_hashes_on_disk.as_ref(),
        &args.default_image_digest,
        config.launcher_config.mpc_hash_override.as_ref(),
    )?;

    pull_with_retry(
        &config.launcher_config.image_reference,
        &manifest_digest,
        config.launcher_config.pull_max_retries,
        config.launcher_config.pull_retry_interval_secs,
        config.launcher_config.pull_max_delay_secs,
    )
    .await?;

    if args.platform == Platform::Tee {
        emit_image_hash_event(&manifest_digest).await?;
    }

    let tee_config = build_tee_config(args.platform, manifest_digest.clone());
    let mpc_node_config =
        intercept_node_config(config.mpc_node_config, &tee_config, args.platform)?;

    write_config_atomically(&mpc_node_config)?;

    launch_mpc_container(
        args.platform,
        &manifest_digest,
        &config.launcher_config.image_reference,
        &config.launcher_config.port_mappings,
    )?;

    Ok(())
}

fn load_config() -> Result<Config, LauncherError> {
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

    validate_image_reference(&config.launcher_config.image_reference)?;

    Ok(config)
}

fn load_approved_hashes(
    default_image_digest: &DockerSha256Digest,
) -> Result<Option<ApprovedHashes>, LauncherError> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(IMAGE_DIGEST_FILE)
    {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                ?err,
                ?default_image_digest,
                "approved hashes file does not exist on disk, falling back to default digest"
            );
            Ok(None)
        }
        Err(err) => Err(LauncherError::FileRead {
            path: IMAGE_DIGEST_FILE.to_string(),
            source: err,
        }),
        Ok(file) => {
            let parsed: ApprovedHashes =
                serde_json::from_reader(file).map_err(|source| LauncherError::JsonParse {
                    path: IMAGE_DIGEST_FILE.to_string(),
                    source,
                })?;
            Ok(Some(parsed))
        }
    }
}

async fn emit_image_hash_event(manifest_digest: &DockerSha256Digest) -> Result<(), LauncherError> {
    let dstack_client = dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

    dstack_client
        .emit_event(
            MPC_IMAGE_HASH_EVENT.to_string(),
            manifest_digest.as_ref().to_vec(),
        )
        .await
        .map_err(|e| LauncherError::DstackEmitEventFailed(e.to_string()))
}

fn build_tee_config(platform: Platform, image_hash: DockerSha256Digest) -> TeeConfig {
    let authority = match platform {
        Platform::Tee => TeeAuthorityConfig::Dstack {
            dstack_endpoint: DSTACK_UNIX_SOCKET.into(),
        },
        Platform::NonTee => TeeAuthorityConfig::Local,
    };

    TeeConfig {
        authority,
        image_hash,
        latest_allowed_hash_file_path: IMAGE_DIGEST_FILE
            .parse()
            .expect("image digest file has a valid path"),
    }
}

fn write_config_atomically(mpc_node_config: &toml::Table) -> Result<(), LauncherError> {
    let mpc_config_toml =
        toml::to_string(mpc_node_config).expect("re-serializing a toml::Table always succeeds");

    let dest = Path::new(MPC_CONFIG_SHARED_PATH);
    let config_dir = dest.parent().unwrap_or(Path::new("/"));

    let mut tmp =
        tempfile::NamedTempFile::new_in(config_dir).map_err(LauncherError::TempFileCreate)?;
    tmp.write_all(mpc_config_toml.as_bytes())
        .map_err(|source| LauncherError::FileWrite {
            path: dest.display().to_string(),
            source,
        })?;
    tmp.persist(dest).map_err(|e| LauncherError::FileWrite {
        path: e.file.path().display().to_string(),
        source: e.error,
    })?;

    Ok(())
}
