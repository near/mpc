use std::io::Write;
use std::process::Command;

use launcher_interface::types::DockerSha256Digest;

use crate::constants::DSTACK_UNIX_SOCKET;
use crate::error::LauncherError;
use crate::types::{Platform, PortMapping, Service};

const COMPOSE_TEMPLATE: &str = include_str!("../assets/mpc-node-docker-compose.template.yml");
const COMPOSE_TEE_TEMPLATE: &str =
    include_str!("../assets/mpc-node-docker-compose.tee.template.yml");

pub fn render_compose_file(
    platform: Platform,
    service: Service,
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
    let command = service
        .command()
        .iter()
        .map(|arg| serde_json::to_string(arg).expect("a string is serializable"))
        .collect::<Vec<_>>()
        .join(", ");

    let rendered = template
        .replace("{{IMAGE_NAME}}", image_name)
        .replace("{{MANIFEST_DIGEST}}", &manifest_digest.to_string())
        .replace("{{CONTAINER_NAME}}", service.container_name())
        .replace("{{COMMAND}}", &command)
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

pub fn launch_container(
    platform: Platform,
    service: Service,
    manifest_digest: &DockerSha256Digest,
    image_name: &str,
    port_mappings: &[PortMapping],
) -> Result<(), LauncherError> {
    tracing::info!(?service, ?manifest_digest, "launching service");

    let compose_file = render_compose_file(
        platform,
        service,
        port_mappings,
        image_name,
        manifest_digest,
    )?;
    let compose_path = compose_file.path().display().to_string();

    // The compose file pins a stable top-level project `name`, so the
    // container is reused across restarts rather than recreated, preserving its
    // logs. Compose recreates it only when the rendered config (e.g. image
    // digest) changes.
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

    tracing::info!(?service, "service launched");
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::num::NonZeroU16;

    use rstest::rstest;

    use super::*;

    const IMAGE_NAME: &str = "nearone/mpc-node";
    const MANIFEST_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MPC_NODE_COMMAND: &str =
        r#"command: ["/app/mpc-node", "start-with-config-file", "/mnt/shared/mpc-config.toml"]"#;

    #[rstest]
    #[case::tee(
        Platform::Tee,
        format!(
            r#"name: mpc-node

services:
  mpc-node:
    image: "{IMAGE_NAME}@{MANIFEST_DIGEST}"
    container_name: "mpc-node"
    restart: on-failure
    security_opt:
      - no-new-privileges:true
    ports: ["11780:11780"]
    environment:
      - "DSTACK_ENDPOINT=/var/run/dstack.sock"
    volumes:
      - /tapp:/tapp:ro
      - shared-volume:/mnt/shared
      - mpc-data:/data
      - "/var/run/dstack.sock:/var/run/dstack.sock"
    {MPC_NODE_COMMAND}

volumes:
  shared-volume:
    name: shared-volume
  mpc-data:
    name: mpc-data
"#
        )
    )]
    #[case::non_tee(
        Platform::NonTee,
        format!(
            r#"name: mpc-node

services:
  mpc-node:
    image: "{IMAGE_NAME}@{MANIFEST_DIGEST}"
    container_name: "mpc-node"
    restart: on-failure
    security_opt:
      - no-new-privileges:true
    ports: ["11780:11780"]
    volumes:
      - /tapp:/tapp:ro
      - shared-volume:/mnt/shared
      - mpc-data:/data
    {MPC_NODE_COMMAND}

volumes:
  shared-volume:
    name: shared-volume
  mpc-data:
    name: mpc-data
"#
        )
    )]
    fn render_compose_file__should_render_the_mpc_node(
        #[case] platform: Platform,
        #[case] expected: String,
    ) {
        // When
        let rendered = render(platform, Service::MpcNode);

        // Then
        assert_eq!(rendered, expected);
    }

    #[rstest]
    fn render_compose_file__should_change_only_the_name_and_command_for_the_backup_service(
        #[values(Platform::Tee, Platform::NonTee)] platform: Platform,
    ) {
        // When
        let rendered = render(platform, Service::BackupService);

        // Then
        let expected = render(platform, Service::MpcNode)
            .replace(
                r#"container_name: "mpc-node""#,
                r#"container_name: "backup-service""#,
            )
            .replace(
                MPC_NODE_COMMAND,
                r#"command: ["/app/backup-cli", "--home-dir", "/data", "start-with-config-file", "/mnt/shared/backup-service-config.toml"]"#,
            );
        assert_eq!(rendered, expected);
    }

    fn render(platform: Platform, service: Service) -> String {
        let port_mappings = [PortMapping {
            host: NonZeroU16::new(11780).unwrap(),
            container: NonZeroU16::new(11780).unwrap(),
        }];
        let manifest_digest: DockerSha256Digest = MANIFEST_DIGEST.parse().unwrap();
        let file = render_compose_file(
            platform,
            service,
            &port_mappings,
            IMAGE_NAME,
            &manifest_digest,
        )
        .unwrap();
        std::fs::read_to_string(file.path()).unwrap()
    }
}
