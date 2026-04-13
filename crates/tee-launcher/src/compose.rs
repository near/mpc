use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;

use launcher_interface::types::DockerSha256Digest;
use serde::Serialize;

use crate::constants::{DSTACK_UNIX_SOCKET, MPC_CONFIG_SHARED_PATH, MPC_CONTAINER_NAME};
use crate::error::LauncherError;
use crate::types::{Platform, PortMapping};

/// Typed docker-compose document. Serialized via `serde_yaml` so that string
/// values (image reference, container name, etc.) are escaped by the YAML
/// serializer — there is no string-level template interpolation, and therefore
/// no YAML-injection surface for caller-controlled fields.
#[derive(Serialize)]
struct ComposeFile {
    services: BTreeMap<String, Service>,
    volumes: BTreeMap<String, NamedVolume>,
}

#[derive(Serialize)]
struct Service {
    image: String,
    container_name: String,
    security_opt: Vec<String>,
    ports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    environment: Vec<String>,
    volumes: Vec<String>,
    command: Vec<String>,
}

#[derive(Serialize)]
struct NamedVolume {
    name: String,
}

fn build_compose(
    platform: Platform,
    port_mappings: &[PortMapping],
    image_name: &str,
    manifest_digest: &DockerSha256Digest,
) -> ComposeFile {
    let mut volumes = vec![
        "/tapp:/tapp:ro".to_string(),
        "shared-volume:/mnt/shared".to_string(),
        "mpc-data:/data".to_string(),
    ];
    let mut environment = Vec::new();

    if platform == Platform::Tee {
        environment.push(format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}"));
        volumes.push(format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}"));
    }

    let service = Service {
        image: format!("{image_name}@{manifest_digest}"),
        container_name: MPC_CONTAINER_NAME.to_string(),
        security_opt: vec!["no-new-privileges:true".to_string()],
        ports: port_mappings
            .iter()
            .map(PortMapping::docker_compose_value)
            .collect(),
        environment,
        volumes,
        command: vec![
            "/app/mpc-node".to_string(),
            "start-with-config-file".to_string(),
            MPC_CONFIG_SHARED_PATH.to_string(),
        ],
    };

    let mut services = BTreeMap::new();
    services.insert(MPC_CONTAINER_NAME.to_string(), service);

    let mut named_volumes = BTreeMap::new();
    named_volumes.insert(
        "shared-volume".to_string(),
        NamedVolume {
            name: "shared-volume".to_string(),
        },
    );
    named_volumes.insert(
        "mpc-data".to_string(),
        NamedVolume {
            name: "mpc-data".to_string(),
        },
    );

    ComposeFile {
        services,
        volumes: named_volumes,
    }
}

pub fn render_compose_file(
    platform: Platform,
    port_mappings: &[PortMapping],
    image_name: &str,
    manifest_digest: &DockerSha256Digest,
) -> Result<tempfile::NamedTempFile, LauncherError> {
    let compose = build_compose(platform, port_mappings, image_name, manifest_digest);
    let rendered = serde_yaml::to_string(&compose).expect("compose struct is always serializable");

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

    /// Parse the rendered compose file as generic YAML for structural assertions.
    /// Using the typed value rather than substring matching makes the tests
    /// robust against serializer quoting decisions.
    fn parse(rendered: &str) -> serde_yaml::Value {
        serde_yaml::from_str(rendered).expect("rendered compose file is valid YAML")
    }

    fn service(doc: &serde_yaml::Value) -> &serde_yaml::Value {
        &doc["services"][MPC_CONTAINER_NAME]
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

    fn string_list(value: &serde_yaml::Value) -> Vec<String> {
        value
            .as_sequence()
            .expect("expected a YAML sequence")
            .iter()
            .map(|v| v.as_str().expect("expected string element").to_string())
            .collect()
    }

    #[test]
    fn rendered_output_is_valid_yaml() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);

        // then — parses without error
        let _doc = parse(&rendered);
    }

    #[test]
    fn tee_mode_includes_dstack_env_and_volume() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::Tee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then
        let env = string_list(&service(&doc)["environment"]);
        assert!(env.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));

        let volumes = string_list(&service(&doc)["volumes"]);
        assert!(volumes.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn nontee_mode_excludes_dstack() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then — no environment key at all, and no dstack volume
        assert!(service(&doc).get("environment").is_none());
        let volumes = string_list(&service(&doc)["volumes"]);
        assert!(!volumes.iter().any(|v| v.contains(DSTACK_UNIX_SOCKET)));
    }

    #[test]
    fn includes_security_opts_and_required_volumes() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then
        let security_opt = string_list(&service(&doc)["security_opt"]);
        assert!(security_opt.contains(&"no-new-privileges:true".to_string()));

        let volumes = string_list(&service(&doc)["volumes"]);
        assert!(volumes.contains(&"/tapp:/tapp:ro".to_string()));
        assert!(volumes.contains(&"shared-volume:/mnt/shared".to_string()));
        assert!(volumes.contains(&"mpc-data:/data".to_string()));

        assert_eq!(
            service(&doc)["container_name"].as_str(),
            Some(MPC_CONTAINER_NAME)
        );
    }

    #[test]
    fn command_starts_mpc_node_with_config_file() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then
        let command = string_list(&service(&doc)["command"]);
        assert_eq!(
            command,
            vec![
                "/app/mpc-node".to_string(),
                "start-with-config-file".to_string(),
                MPC_CONFIG_SHARED_PATH.to_string(),
            ]
        );
    }

    #[test]
    fn image_is_set_to_name_at_digest() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then
        assert_eq!(
            service(&doc)["image"].as_str(),
            Some(format!("{SAMPLE_IMAGE_NAME}@{digest}").as_str())
        );
    }

    #[test]
    fn includes_ports() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &port_mappings_with_port(), &digest);
        let doc = parse(&rendered);

        // then
        let ports = string_list(&service(&doc)["ports"]);
        assert_eq!(ports, vec!["11780:11780".to_string()]);
    }

    #[test]
    fn named_volumes_are_declared() {
        // given
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, &empty_port_mappings(), &digest);
        let doc = parse(&rendered);

        // then
        assert_eq!(
            doc["volumes"]["shared-volume"]["name"].as_str(),
            Some("shared-volume")
        );
        assert_eq!(
            doc["volumes"]["mpc-data"]["name"].as_str(),
            Some("mpc-data")
        );
    }

    /// Regression test for the injection class the old `validate_image_reference`
    /// was guarding against. With structural serialization, a caller-controlled
    /// image reference cannot break out of its YAML scalar regardless of what
    /// bytes it contains — the serializer escapes and quotes as needed.
    #[test]
    fn image_reference_with_injection_chars_does_not_break_yaml() {
        // given — an image_name containing characters that would have been
        // rejected by the old allowlist validator
        let digest = sample_digest();
        let evil_image_name = "evil\"\n  injected: true\n#";

        // when
        let file = render_compose_file(
            Platform::NonTee,
            &empty_port_mappings(),
            evil_image_name,
            &digest,
        )
        .unwrap();
        let rendered = std::fs::read_to_string(file.path()).unwrap();
        let doc = parse(&rendered);

        // then — the full string (including the \" and \n) round-trips as a
        // single scalar, and no stray top-level key was introduced
        assert_eq!(
            service(&doc)["image"].as_str(),
            Some(format!("{evil_image_name}@{digest}").as_str())
        );
        assert!(doc.get("injected").is_none());
    }
}
