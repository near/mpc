//! Config loading. The dstack `user-config.toml` wraps the node config in an
//! opaque `[mpc_node_config]` table the launcher patches before it becomes a
//! `StartConfig`, so there is no single whole-config type to reuse. Instead we
//! locate the `foreign_chains` subtree wherever it lives and deserialize just
//! that into the canonical [`ForeignChainsConfig`].

use std::path::Path;

use anyhow::{Context, bail};
use mpc_node_config::{ChainId, ForeignChainsConfig};
use serde::Deserialize;
use serde::de::IntoDeserializer;
use serde::de::value::{Error as ValueError, StrDeserializer};

use foreign_chain_health_check::{ExpectedIdentities, Network};

/// Paths where `foreign_chains` may live, most-nested first so a wrapped config
/// matches before a barer one.
const FOREIGN_CHAINS_PATHS: &[&[&str]] = &[
    &["mpc_node_config", "node", "foreign_chains"],
    &["node", "foreign_chains"],
    &["foreign_chains"],
];

const CHAIN_ID_PATHS: &[&[&str]] = &[
    &["mpc_node_config", "near_init", "chain_id"],
    &["near_init", "chain_id"],
];

const CONTRACT_ID_PATHS: &[&[&str]] = &[
    &["mpc_node_config", "node", "indexer", "mpc_contract_id"],
    &["node", "indexer", "mpc_contract_id"],
    &["indexer", "mpc_contract_id"],
];

/// Where the per-chain expected identities live: an `identities` map (chain label ->
/// expected identity) under a sibling of `foreign_chains`.
const EXPECTED_IDENTITY_PATHS: &[&[&str]] = &[
    &[
        "mpc_node_config",
        "node",
        "foreign_chain_health_check",
        "identities",
    ],
    &["node", "foreign_chain_health_check", "identities"],
    &["foreign_chain_health_check", "identities"],
];

fn classify_network(chain_id: Option<&str>, contract_id: Option<&str>) -> Option<Network> {
    let parsed = chain_id.and_then(|id| {
        let de: StrDeserializer<'_, ValueError> = id.into_deserializer();
        ChainId::deserialize(de).ok()
    });
    match parsed {
        Some(ChainId::Mainnet) => return Some(Network::Mainnet),
        Some(ChainId::Testnet) => return Some(Network::Testnet),
        _ => {}
    }
    match contract_id {
        Some(id) if id.ends_with(".testnet") => Some(Network::Testnet),
        Some(id) if id.ends_with(".near") || id == "v1.signer" => Some(Network::Mainnet),
        _ => None,
    }
}

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

/// Deserializes the subtree at the first of `paths` present in the config into `T`;
/// `T::default()` when none matches.
fn find_and_parse<T>(
    contents: &str,
    path: &Path,
    paths: &[&[&str]],
    what: &str,
) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    match format_from_path(path)? {
        Format::Yaml => {
            let root: serde_yaml::Value =
                serde_yaml::from_str(contents).context("parse YAML config")?;
            for keys in paths {
                if let Some(section) = keys.iter().try_fold(&root, |v, k| v.get(k)) {
                    return serde_yaml::from_value(section.clone())
                        .with_context(|| format!("parse {what} section"));
                }
            }
            Ok(T::default())
        }
        Format::Toml => {
            let root: toml::Value = toml::from_str(contents).context("parse TOML config")?;
            for keys in paths {
                if let Some(section) = keys.iter().try_fold(&root, |v, k| v.get(*k)) {
                    return section
                        .clone()
                        .try_into()
                        .with_context(|| format!("parse {what} section"));
                }
            }
            Ok(T::default())
        }
    }
}

/// Empty when no `foreign_chains` section is present.
pub fn parse_foreign_chains(contents: &str, path: &Path) -> anyhow::Result<ForeignChainsConfig> {
    find_and_parse(contents, path, FOREIGN_CHAINS_PATHS, "foreign_chains")
}

fn toml_str<'a>(root: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(root, |v, k| v.get(*k))?.as_str()
}

fn yaml_str<'a>(root: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(root, |v, k| v.get(k))?.as_str()
}

/// Per-chain expected identities from config. Absent chains stay `None` (their check then
/// fails until configured); an unknown chain key or non-string value is a hard error.
pub fn detect_expected_identities(
    contents: &str,
    path: &Path,
) -> anyhow::Result<ExpectedIdentities> {
    find_and_parse(
        contents,
        path,
        EXPECTED_IDENTITY_PATHS,
        "foreign_chain_health_check.identities",
    )
}

/// `None` when the config carries no conclusive network signal.
pub fn detect_network(contents: &str, path: &Path) -> anyhow::Result<Option<Network>> {
    Ok(match format_from_path(path)? {
        Format::Yaml => {
            let root: serde_yaml::Value =
                serde_yaml::from_str(contents).context("parse YAML config")?;
            classify_network(
                CHAIN_ID_PATHS.iter().find_map(|p| yaml_str(&root, p)),
                CONTRACT_ID_PATHS.iter().find_map(|p| yaml_str(&root, p)),
            )
        }
        Format::Toml => {
            let root: toml::Value = toml::from_str(contents).context("parse TOML config")?;
            classify_network(
                CHAIN_ID_PATHS.iter().find_map(|p| toml_str(&root, p)),
                CONTRACT_ID_PATHS.iter().find_map(|p| toml_str(&root, p)),
            )
        }
    })
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

    #[test]
    fn detect_network__should_read_chain_id_from_dstack_toml() {
        // Given
        let toml = "[mpc_node_config.near_init]\nchain_id = \"testnet\"\n";

        // When
        let network = detect_network(toml, Path::new("user-config.toml")).unwrap();

        // Then
        assert_eq!(network, Some(Network::Testnet));
    }

    #[test]
    fn detect_network__should_fall_back_to_contract_id() {
        // Given
        let yaml = "indexer:\n  mpc_contract_id: v1.signer-prod.testnet\n";

        // When
        let network = detect_network(yaml, Path::new("config.yaml")).unwrap();

        // Then
        assert_eq!(network, Some(Network::Testnet));
    }

    #[test]
    fn detect_network__should_classify_mainnet_contract_id() {
        // Given
        let yaml = "indexer:\n  mpc_contract_id: v1.signer\n";

        // When
        let network = detect_network(yaml, Path::new("config.yaml")).unwrap();

        // Then
        assert_eq!(network, Some(Network::Mainnet));
    }

    #[test]
    fn detect_network__should_return_none_without_signal() {
        // Given
        // When
        let network = detect_network("home_dir = \"/data\"\n", Path::new("config.toml")).unwrap();

        // Then
        assert_eq!(network, None);
    }

    #[test]
    fn detect_expected_identities__should_read_seeded_value_from_dstack_toml() {
        // Given an `identities` map nested under the dstack `mpc_node_config.node` prefix
        let toml = "[mpc_node_config.node.foreign_chain_health_check.identities]\n\
                    starknet = \"0x534e5f4d41494e\"\n";

        // When
        let ids = detect_expected_identities(toml, Path::new("user-config.toml")).unwrap();

        // Then
        assert_eq!(ids.starknet.as_deref(), Some("0x534e5f4d41494e"));
    }

    #[test]
    fn detect_expected_identities__should_read_seeded_value_from_top_level_yaml() {
        // Given
        let yaml = "foreign_chain_health_check:\n  identities:\n    starknet: \"0x534e5f5345504f4c4941\"\n";

        // When
        let ids = detect_expected_identities(yaml, Path::new("config.yaml")).unwrap();

        // Then
        assert_eq!(ids.starknet.as_deref(), Some("0x534e5f5345504f4c4941"));
    }

    #[test]
    fn detect_expected_identities__should_reject_non_string_value() {
        // Given a known chain's identity mistyped as a number (easy to do in TOML)
        let toml = "[foreign_chain_health_check.identities]\nstarknet = 1\n";

        // When / Then — a loud parse error, not a silently dropped entry
        detect_expected_identities(toml, Path::new("config.toml")).unwrap_err();
    }

    #[test]
    fn detect_expected_identities__should_reject_unknown_chain_key() {
        // Given a misspelled chain label
        let toml = "[foreign_chain_health_check.identities]\nstartknet = \"0x1\"\n";

        // When / Then — the typo errors instead of silently doing nothing
        detect_expected_identities(toml, Path::new("config.toml")).unwrap_err();
    }

    #[test]
    fn detect_expected_identities__should_be_empty_when_absent() {
        // Given / When
        let ids =
            detect_expected_identities("home_dir = \"/data\"\n", Path::new("config.toml")).unwrap();

        // Then
        assert!(ids.starknet.is_none() && ids.sui.is_none());
    }
}
