use std::io::Write;
use std::process::Command;

use launcher_interface::types::DockerSha256Digest;

use crate::constants::{DSTACK_UNIX_SOCKET, MPC_CONFIG_SHARED_PATH, MPC_CONTAINER_NAME};
use crate::error::LauncherError;
use crate::types::{Platform, PortMapping};

const COMPOSE_TEMPLATE: &str = include_str!("../assets/mpc-node-docker-compose.template.yml");
const COMPOSE_TEE_TEMPLATE: &str =
    include_str!("../assets/mpc-node-docker-compose.tee.template.yml");

pub fn render_compose_file(
    platform: Platform,
    port_mappings: &[PortMapping],
    image_name: &str,
    manifest_digest: &DockerSha256Digest,
) -> Result<tempfile::NamedTempFile, LauncherError> {
    let template = match platform {
        Platform::Tee => COMPOSE_TEE_TEMPLATE,
        Platform::NonTee => COMPOSE_TEMPLATE,
    };

    let ports: Vec<String> = port_mappings
        .iter()
        .map(PortMapping::docker_compose_value)
        .collect();
    let ports_json = serde_json::to_string(&ports).expect("port list is serializable");

    let rendered = template
        .replace("{{IMAGE_NAME}}", image_name)
        .replace("{{MANIFEST_DIGEST}}", &manifest_digest.to_string())
        .replace("{{CONTAINER_NAME}}", MPC_CONTAINER_NAME)
        .replace("{{MPC_CONFIG_SHARED_PATH}}", MPC_CONFIG_SHARED_PATH)
        .replace("{{DSTACK_UNIX_SOCKET}}", DSTACK_UNIX_SOCKET)
        .replace("{{PORTS}}", &ports_json);

    tracing::info!(compose = %rendered, "rendered docker-compose file");

    let mut file = tempfile::NamedTempFile::new().map_err(LauncherError::TempFileCreate)?;
    file.write_all(rendered.as_bytes())
        .map_err(|source| LauncherError::FileWrite {
            path: file.path().display().to_string(),
            source,
        })?;

    Ok(file)
}

pub fn launch_mpc_container(
    platform: Platform,
    manifest_digest: &DockerSha256Digest,
    image_name: &str,
    port_mappings: &[PortMapping],
) -> Result<(), LauncherError> {
    tracing::info!(?manifest_digest, "launching MPC node");

    let compose_file = render_compose_file(platform, port_mappings, image_name, manifest_digest)?;
    let compose_path = compose_file.path().display().to_string();

    // Remove any existing container from a previous run (by name, independent of compose file)
    let _ = Command::new("docker")
        .args(["rm", "-f", MPC_CONTAINER_NAME])
        .output();

    let run_output = Command::new("docker")
        .args(["compose", "-f", &compose_path, "up", "-d"])
        .output()
        .map_err(|inner| LauncherError::DockerRunFailed {
            image_hash: manifest_digest.clone(),
            inner,
        })?;

    if !run_output.status.success() {
        let stderr = String::from_utf8_lossy(&run_output.stderr);
        let stdout = String::from_utf8_lossy(&run_output.stdout);
        tracing::error!(%stderr, %stdout, "docker compose up failed");
        return Err(LauncherError::DockerRunFailedExitStatus {
            image_hash: manifest_digest.clone(),
            output: stderr.into_owned(),
        });
    }

    tracing::info!("MPC launched successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use launcher_interface::types::DockerSha256Digest;

    use super::*;

    const SAMPLE_IMAGE_NAME: &str = "nearone/mpc-node";

    fn render(
        platform: Platform,
        port_mappings: &[PortMapping],
        digest: &DockerSha256Digest,
    ) -> String {
        let file = render_compose_file(platform, port_mappings, SAMPLE_IMAGE_NAME, digest).unwrap();
        std::fs::read_to_string(file.path()).unwrap()
    }

    fn digest(hex_char: char) -> DockerSha256Digest {
        format!(
            "sha256:{}",
            std::iter::repeat_n(hex_char, 64).collect::<String>()
        )
        .parse()
        .unwrap()
    }

    fn sample_digest() -> DockerSha256Digest {
        digest('a')
    }

    fn empty_port_mappings() -> Vec<PortMapping> {
        vec![]
    }

    fn port_mappings_with_port() -> Vec<PortMapping> {
        vec![PortMapping {
            host: NonZeroU16::new(11780).unwrap(),
            container: NonZeroU16::new(11780).unwrap(),
        }]
    }

    #[test]
    fn tee_mode_includes_dstack_env_and_volume() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::Tee, &port_mappings, &digest);

        // then
        assert!(rendered.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
        assert!(rendered.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn nontee_mode_excludes_dstack() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(!rendered.contains("DSTACK_ENDPOINT"));
        assert!(!rendered.contains(DSTACK_UNIX_SOCKET));
    }

    #[test]
    fn includes_security_opts_and_required_volumes() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(rendered.contains("no-new-privileges:true"));
        assert!(rendered.contains("/tapp:/tapp:ro"));
        assert!(rendered.contains("shared-volume:/mnt/shared"));
        assert!(rendered.contains("mpc-data:/data"));
        assert!(rendered.contains(&format!("container_name: \"{MPC_CONTAINER_NAME}\"")));
    }

    #[test]
    fn tee_mode_includes_restart_on_failure() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::Tee, &port_mappings, &digest);

        // then
        assert!(rendered.contains("restart: on-failure"));
    }

    #[test]
    fn nontee_mode_includes_restart_on_failure() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(rendered.contains("restart: on-failure"));
    }

    #[test]
    fn mounts_config_file_read_only() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then — config is on the shared volume, referenced in the command
        assert!(rendered.contains(MPC_CONFIG_SHARED_PATH));
    }

    #[test]
    fn includes_start_with_config_file_command() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(rendered.contains("/app/mpc-node"));
        assert!(rendered.contains(MPC_CONFIG_SHARED_PATH));
    }

    #[test]
    fn image_is_set() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(rendered.contains(&format!("image: \"{SAMPLE_IMAGE_NAME}@{digest}\"")));
    }

    #[test]
    fn includes_ports() {
        // given
        let port_mappings = port_mappings_with_port();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(rendered.contains("11780:11780"));
    }

    #[test]
    fn no_env_section_in_nontee_mode() {
        // given
        let port_mappings = empty_port_mappings();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings, &digest);

        // then
        assert!(!rendered.contains("environment:"));
    }
}
