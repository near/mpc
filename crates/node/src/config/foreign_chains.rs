use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignChainsConfig {
    #[serde(default)]
    pub solana: Option<SolanaChainConfig>,
    #[serde(default)]
    pub bitcoin: Option<BitcoinChainConfig>,
    #[serde(default)]
    pub ethereum: Option<EthereumChainConfig>,
}

impl ForeignChainsConfig {
    pub fn is_empty(&self) -> bool {
        self.solana.is_none() && self.bitcoin.is_none() && self.ethereum.is_none()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(config) = &self.solana {
            config.validate()?;
        }
        if let Some(config) = &self.bitcoin {
            config.validate()?;
        }
        if let Some(config) = &self.ethereum {
            config.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SolanaApiVariant {
    Standard,
    Alchemy,
    Helius,
    Quicknode,
    Ankr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EthereumApiVariant {
    Standard,
    Alchemy,
    Infura,
    Quicknode,
    Ankr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BitcoinApiVariant {
    Standard,
    #[serde(alias = "blockstream")]
    #[serde(alias = "mempool-space")]
    Esplora,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, SolanaProviderConfig>,
}

impl SolanaChainConfig {
    fn validate(&self) -> anyhow::Result<()> {
        validate_chain_config(
            "solana",
            self.timeout_sec,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("solana", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, BitcoinProviderConfig>,
}

impl BitcoinChainConfig {
    fn validate(&self) -> anyhow::Result<()> {
        validate_chain_config(
            "bitcoin",
            self.timeout_sec,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("bitcoin", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, EthereumProviderConfig>,
}

impl EthereumChainConfig {
    fn validate(&self) -> anyhow::Result<()> {
        validate_chain_config(
            "ethereum",
            self.timeout_sec,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("ethereum", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaProviderConfig {
    pub rpc_url: String,
    pub api_variant: SolanaApiVariant,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl SolanaProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinProviderConfig {
    pub rpc_url: String,
    pub api_variant: BitcoinApiVariant,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl BitcoinProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumProviderConfig {
    pub rpc_url: String,
    pub api_variant: EthereumApiVariant,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl EthereumProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthConfig {
    None,
    Header {
        name: String,
        #[serde(default)]
        scheme: Option<String>,
        token: TokenConfig,
    },
    Path {
        placeholder: String,
        token: TokenConfig,
    },
    Query {
        name: String,
        token: TokenConfig,
    },
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenConfig {
    Env { env: String },
    Val { val: String },
}

impl TokenConfig {
    pub fn resolve(&self) -> anyhow::Result<String> {
        match self {
            TokenConfig::Env { env } => {
                std::env::var(env).with_context(|| format!("environment variable {env} is not set"))
            }
            TokenConfig::Val { val } => Ok(val.clone()),
        }
    }
}

fn validate_chain_config<P>(
    chain_label: &str,
    timeout_sec: u64,
    providers: &BTreeMap<String, P>,
    rpc_url: impl Fn(&P) -> &str,
    validate_provider: impl Fn(&P, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        timeout_sec > 0,
        "foreign_chains.{chain_label}.timeout_sec must be > 0"
    );
    anyhow::ensure!(
        !providers.is_empty(),
        "foreign_chains.{chain_label} must include at least one provider"
    );

    let mut seen_rpc_urls = BTreeSet::new();
    for (provider_name, provider) in providers {
        let provider_rpc_url = rpc_url(provider);
        anyhow::ensure!(
            !provider_rpc_url.trim().is_empty(),
            "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url must be non-empty"
        );
        anyhow::ensure!(
            seen_rpc_urls.insert(provider_rpc_url.to_string()),
            "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url duplicates another provider URL"
        );
        validate_provider(provider, provider_name)
            .with_context(|| format!("invalid provider {provider_name} for {chain_label}"))?;
    }

    Ok(())
}

fn validate_auth_config(
    auth: &AuthConfig,
    rpc_url: &str,
    chain_label: &str,
    provider_name: &str,
) -> anyhow::Result<()> {
    match auth {
        AuthConfig::None => Ok(()),
        AuthConfig::Header { name, scheme, .. } => {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.name must be non-empty"
            );
            if let Some(scheme) = scheme {
                anyhow::ensure!(
                    !scheme.trim().is_empty(),
                    "foreign_chains.{chain_label}.providers.{provider_name}.auth.scheme must be non-empty if provided"
                );
            }
            Ok(())
        }
        AuthConfig::Path { placeholder, .. } => {
            anyhow::ensure!(
                !placeholder.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.placeholder must be non-empty"
            );
            anyhow::ensure!(
                rpc_url.contains(placeholder),
                "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url must include the path placeholder"
            );
            Ok(())
        }
        AuthConfig::Query { name, .. } => {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.name must be non-empty"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;

    #[test]
    fn config_parsing__should_succeed_when_foreign_chains_are_unset() -> anyhow::Result<()> {
        // Given
        let yaml = r#"
my_near_account_id: test.near
near_responder_account_id: test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8080
migration_web_ui:
  host: localhost
  port: 8081
pprof_bind_address: 127.0.0.1:34001
indexer:
  validate_genesis: false
  sync_mode: Latest
  finality: optimistic
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
triple:
  concurrency: 1
  desired_triples_to_buffer: 1
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 1
  desired_presignatures_to_buffer: 1
  timeout_sec: 60
signature:
  timeout_sec: 60
ckd:
  timeout_sec: 60
"#;

        // When
        let config: ConfigFile = serde_yaml::from_str(yaml)?;

        // Then
        config.validate()?;
        assert!(config.foreign_chains.is_empty());
        Ok(())
    }

    #[test]
    fn config_parsing__should_succeed_when_foreign_chains_are_set() -> anyhow::Result<()> {
        // Given
        let yaml = r#"
my_near_account_id: test.near
near_responder_account_id: test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8080
migration_web_ui:
  host: localhost
  port: 8081
pprof_bind_address: 127.0.0.1:34001
indexer:
  validate_genesis: false
  sync_mode: Latest
  finality: optimistic
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
triple:
  concurrency: 1
  desired_triples_to_buffer: 1
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 1
  desired_presignatures_to_buffer: 1
  timeout_sec: 60
signature:
  timeout_sec: 60
ckd:
  timeout_sec: 60
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        api_variant: alchemy
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
      quicknode:
        api_variant: quicknode
        rpc_url: "https://your-endpoint.solana-mainnet.quiknode.pro/"
        auth:
          kind: header
          name: x-api-key
          token:
            val: "local"
      ankr:
        api_variant: ankr
        rpc_url: "https://rpc.ankr.com/near/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            env: ANKR_API_KEY
      public:
        api_variant: standard
        rpc_url: "https://rpc.public.example.com"
        auth:
          kind: none
      query:
        api_variant: standard
        rpc_url: "https://rpc.example.com"
        auth:
          kind: query
          name: api_key
          token:
            val: "local"
  bitcoin:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: esplora
        rpc_url: "https://blockstream.info/api"
        auth:
          kind: none
  ethereum:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        api_variant: alchemy
        rpc_url: "https://eth-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
"#;

        // When
        let config: ConfigFile = serde_yaml::from_str(yaml)?;

        // Then
        config.validate()?;
        assert!(config.foreign_chains.solana.is_some());
        assert!(config.foreign_chains.bitcoin.is_some());
        assert!(config.foreign_chains.ethereum.is_some());
        Ok(())
    }

    #[test]
    fn config_parsing__should_fail_when_api_variant_is_missing() {
        // Given
        let yaml = r#"
my_near_account_id: test.near
near_responder_account_id: test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8080
migration_web_ui:
  host: localhost
  port: 8081
pprof_bind_address: 127.0.0.1:34001
indexer:
  validate_genesis: false
  sync_mode: Latest
  finality: optimistic
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
triple:
  concurrency: 1
  desired_triples_to_buffer: 1
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 1
  desired_presignatures_to_buffer: 1
  timeout_sec: 60
signature:
  timeout_sec: 60
ckd:
  timeout_sec: 60
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
"#;

        // When
        let result: Result<ConfigFile, _> = serde_yaml::from_str(yaml);

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn config_parsing__should_fail_when_api_variant_is_invalid_for_chain() {
        // Given
        let yaml = r#"
my_near_account_id: test.near
near_responder_account_id: test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8080
migration_web_ui:
  host: localhost
  port: 8081
pprof_bind_address: 127.0.0.1:34001
indexer:
  validate_genesis: false
  sync_mode: Latest
  finality: optimistic
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
triple:
  concurrency: 1
  desired_triples_to_buffer: 1
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 1
  desired_presignatures_to_buffer: 1
  timeout_sec: 60
signature:
  timeout_sec: 60
ckd:
  timeout_sec: 60
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        api_variant: infura
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
"#;

        // When
        let result: Result<ConfigFile, _> = serde_yaml::from_str(yaml);

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn config_parsing__should_fail_when_foreign_chain_key_is_unknown() {
        // Given
        let yaml = r#"
my_near_account_id: test.near
near_responder_account_id: test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8080
migration_web_ui:
  host: localhost
  port: 8081
pprof_bind_address: 127.0.0.1:34001
indexer:
  validate_genesis: false
  sync_mode: Latest
  finality: optimistic
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
triple:
  concurrency: 1
  desired_triples_to_buffer: 1
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 1
  desired_presignatures_to_buffer: 1
  timeout_sec: 60
signature:
  timeout_sec: 60
ckd:
  timeout_sec: 60
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        api_variant: alchemy
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
  polygon:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: standard
        rpc_url: "https://rpc.public.example.com"
        auth:
          kind: none
"#;

        // When
        let result: Result<ConfigFile, _> = serde_yaml::from_str(yaml);

        // Then
        assert!(result.is_err());
    }
}
