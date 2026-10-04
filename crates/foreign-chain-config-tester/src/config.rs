//! Config loading. The dstack `user-config.toml` wraps the node config in an
//! opaque `[mpc_node_config]` table the launcher patches before it becomes a
//! [`StartConfig`](mpc_node_config::StartConfig), so there is no single whole-config type to reuse. Instead we
//! locate the `foreign_chains` subtree wherever it lives and deserialize just
//! that into the canonical [`ForeignChainsConfig`].

use std::path::Path;

use anyhow::{Context, bail};
use mpc_node_config::ForeignChainsConfig;

/// Paths where `foreign_chains` may live, most-nested first so a wrapped config
/// matches before a barer one.
const FOREIGN_CHAINS_PATHS: &[&[&str]] = &[
    &["mpc_node_config", "node", "foreign_chains"],
    &["node", "foreign_chains"],
    &["foreign_chains"],
];

enum Format {
    Yaml,
    Toml,
}

fn format_from_path(path: &Path) -> anyhow::Result<Format> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => Ok(Format::Yaml),
        Some("toml") => Ok(Format::Toml),
        other => bail!("unsupported config extension {other:?}; expected .yaml, .yml, or .toml"),
    }
}

/// Empty when no `foreign_chains` section is present.
pub fn parse_foreign_chains(contents: &str, path: &Path) -> anyhow::Result<ForeignChainsConfig> {
    match format_from_path(path)? {
        Format::Yaml => {
            let root: serde_yaml::Value =
                serde_yaml::from_str(contents).context("parse YAML config")?;
            for keys in FOREIGN_CHAINS_PATHS {
                if let Some(section) = keys.iter().try_fold(&root, |v, k| v.get(k)) {
                    return serde_yaml::from_value(section.clone())
                        .context("parse foreign_chains section");
                }
            }
            Ok(ForeignChainsConfig::default())
        }
        Format::Toml => {
            let root: toml::Value = toml::from_str(contents).context("parse TOML config")?;
            for keys in FOREIGN_CHAINS_PATHS {
                if let Some(section) = keys.iter().try_fold(&root, |v, k| v.get(*k)) {
                    return section
                        .clone()
                        .try_into()
                        .context("parse foreign_chains section");
                }
            }
            Ok(ForeignChainsConfig::default())
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    const DSTACK_TOML: &str = r#"
[launcher_config]
image_reference = "nearone/mpc-node:3.10.0"

[mpc_node_config]
home_dir = "/data"

[mpc_node_config.node.foreign_chains.base]
timeout_sec = 30
max_retries = 3
expected_network_fingerprint = "8453"

[mpc_node_config.node.foreign_chains.base.providers.official]
rpc_url = "https://mainnet.base.org"

[mpc_node_config.node.foreign_chains.base.providers.official.auth]
kind = "none"
"#;

    const LAUNCHER_TOML: &str = r#"
home_dir = "/data"

[node.foreign_chains.base]
timeout_sec = 30
max_retries = 3

[node.foreign_chains.base.providers.official]
rpc_url = "https://mainnet.base.org"

[node.foreign_chains.base.providers.official.auth]
kind = "none"
"#;

    const LEGACY_YAML: &str = r#"
my_near_account_id: sam.test.near
foreign_chains:
  base:
    timeout_sec: 30
    max_retries: 3
    providers:
      official:
        rpc_url: "https://mainnet.base.org"
        auth:
          kind: none
"#;

    #[test]
    fn parse_foreign_chains__should_read_dstack_user_config_toml() {
        // Given
        // When
        let fc = parse_foreign_chains(DSTACK_TOML, Path::new("user-config.toml")).unwrap();

        // Then
        assert!(fc.base.is_some());
    }

    #[test]
    fn parse_foreign_chains__should_read_launcher_start_config_toml() {
        // Given
        // When
        let fc = parse_foreign_chains(LAUNCHER_TOML, Path::new("config.toml")).unwrap();

        // Then
        assert!(fc.base.is_some());
    }

    #[test]
    fn parse_foreign_chains__should_read_top_level_legacy_yaml() {
        // Given
        // When
        let fc = parse_foreign_chains(LEGACY_YAML, Path::new("config.yaml")).unwrap();

        // Then
        assert!(fc.base.is_some());
    }

    #[test]
    fn parse_foreign_chains__should_return_empty_when_section_absent() {
        // Given
        // When
        let fc = parse_foreign_chains("home_dir = \"/data\"\n", Path::new("config.toml")).unwrap();

        // Then
        assert!(fc.is_empty());
    }

    #[test]
    fn parse_foreign_chains__should_reject_unknown_extension() {
        // Given / When
        let result = parse_foreign_chains("", Path::new("config.json"));

        // Then
        let error = result.unwrap_err().to_string();
        assert!(error.contains("unsupported config extension"), "{error}");
    }
}
