use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignChainsConfig {
    #[serde(default)]
    pub solana: Option<ForeignChainNodeConfig>,
    #[serde(default)]
    pub bitcoin: Option<ForeignChainNodeConfig>,
    #[serde(default)]
    pub ethereum: Option<ForeignChainNodeConfig>,
    #[serde(default)]
    pub base: Option<ForeignChainNodeConfig>,
    #[serde(default)]
    pub bnb: Option<ForeignChainNodeConfig>,
    #[serde(default)]
    pub arbitrum: Option<ForeignChainNodeConfig>,
}

impl ForeignChainsConfig {
    pub fn is_empty(&self) -> bool {
        self.solana.is_none()
            && self.bitcoin.is_none()
            && self.ethereum.is_none()
            && self.base.is_none()
            && self.bnb.is_none()
            && self.arbitrum.is_none()
    }

    pub fn iter(&self) -> impl Iterator<Item = (ForeignChainName, &ForeignChainNodeConfig)> {
        [
            (ForeignChainName::Solana, self.solana.as_ref()),
            (ForeignChainName::Bitcoin, self.bitcoin.as_ref()),
            (ForeignChainName::Ethereum, self.ethereum.as_ref()),
            (ForeignChainName::Base, self.base.as_ref()),
            (ForeignChainName::Bnb, self.bnb.as_ref()),
            (ForeignChainName::Arbitrum, self.arbitrum.as_ref()),
        ]
        .into_iter()
        .filter_map(|(chain, config)| config.map(|cfg| (chain, cfg)))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for (chain, chain_config) in self.iter() {
            chain_config.validate(chain)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ForeignChainName {
    Solana,
    Bitcoin,
    Ethereum,
    Base,
    Bnb,
    Arbitrum,
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

impl SolanaApiVariant {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "standard" => Some(Self::Standard),
            "alchemy" => Some(Self::Alchemy),
            "helius" => Some(Self::Helius),
            "quicknode" => Some(Self::Quicknode),
            "ankr" => Some(Self::Ankr),
            _ => None,
        }
    }

    fn allowed_values() -> &'static [&'static str] {
        &["standard", "alchemy", "helius", "quicknode", "ankr"]
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EvmApiVariant {
    Standard,
    Alchemy,
    Infura,
    Quicknode,
    Ankr,
}

impl EvmApiVariant {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "standard" => Some(Self::Standard),
            "alchemy" => Some(Self::Alchemy),
            "infura" => Some(Self::Infura),
            "quicknode" => Some(Self::Quicknode),
            "ankr" => Some(Self::Ankr),
            _ => None,
        }
    }

    fn allowed_values() -> &'static [&'static str] {
        &["standard", "alchemy", "infura", "quicknode", "ankr"]
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BitcoinApiVariant {
    Standard,
    Esplora,
}

impl BitcoinApiVariant {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "standard" => Some(Self::Standard),
            "esplora" | "blockstream" | "mempool-space" => Some(Self::Esplora),
            _ => None,
        }
    }

    fn allowed_values() -> &'static [&'static str] {
        &["standard", "esplora", "blockstream", "mempool-space"]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainApiVariant {
    Solana(SolanaApiVariant),
    Bitcoin(BitcoinApiVariant),
    Evm(EvmApiVariant),
}

impl ChainApiVariant {
    fn parse(chain: ForeignChainName, raw: &str) -> Option<Self> {
        match chain {
            ForeignChainName::Solana => SolanaApiVariant::parse(raw).map(Self::Solana),
            ForeignChainName::Bitcoin => BitcoinApiVariant::parse(raw).map(Self::Bitcoin),
            ForeignChainName::Ethereum
            | ForeignChainName::Base
            | ForeignChainName::Bnb
            | ForeignChainName::Arbitrum => EvmApiVariant::parse(raw).map(Self::Evm),
        }
    }

    fn allowed_values(chain: ForeignChainName) -> &'static [&'static str] {
        match chain {
            ForeignChainName::Solana => SolanaApiVariant::allowed_values(),
            ForeignChainName::Bitcoin => BitcoinApiVariant::allowed_values(),
            ForeignChainName::Ethereum
            | ForeignChainName::Base
            | ForeignChainName::Bnb
            | ForeignChainName::Arbitrum => EvmApiVariant::allowed_values(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForeignChainNodeConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, ProviderConfig>,
}

impl ForeignChainNodeConfig {
    fn validate(&self, chain: ForeignChainName) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.timeout_sec > 0,
            "foreign_chains.{:?}.timeout_sec must be > 0",
            chain
        );
        anyhow::ensure!(
            !self.providers.is_empty(),
            "foreign_chains.{:?} must include at least one provider",
            chain
        );

        let mut seen_rpc_urls = BTreeSet::new();
        for (provider_name, provider) in &self.providers {
            anyhow::ensure!(
                !provider.rpc_url.trim().is_empty(),
                "foreign_chains.{:?}.providers.{}.rpc_url must be non-empty",
                chain,
                provider_name
            );
            anyhow::ensure!(
                seen_rpc_urls.insert(provider.rpc_url.clone()),
                "foreign_chains.{:?}.providers.{}.rpc_url duplicates another provider URL",
                chain,
                provider_name
            );
            provider
                .validate(chain, provider_name)
                .with_context(|| format!("invalid provider {provider_name} for {chain:?}"))?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub rpc_url: String,
    pub api_variant: String,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl ProviderConfig {
    fn validate(&self, chain: ForeignChainName, provider_name: &str) -> anyhow::Result<()> {
        self.api_variant_for_chain(chain).with_context(|| {
            format!(
                "foreign_chains.{:?}.providers.{}.api_variant must be one of {:?}",
                chain,
                provider_name,
                ChainApiVariant::allowed_values(chain)
            )
        })?;
        match &self.auth {
            AuthConfig::None => Ok(()),
            AuthConfig::Header { name, scheme, .. } => {
                anyhow::ensure!(
                    !name.trim().is_empty(),
                    "foreign_chains.{:?}.providers.{}.auth.name must be non-empty",
                    chain,
                    provider_name
                );
                if let Some(scheme) = scheme {
                    anyhow::ensure!(
                        !scheme.trim().is_empty(),
                        "foreign_chains.{:?}.providers.{}.auth.scheme must be non-empty if provided",
                        chain,
                        provider_name
                    );
                }
                Ok(())
            }
            AuthConfig::Path { placeholder, .. } => {
                anyhow::ensure!(
                    !placeholder.trim().is_empty(),
                    "foreign_chains.{:?}.providers.{}.auth.placeholder must be non-empty",
                    chain,
                    provider_name
                );
                anyhow::ensure!(
                    self.rpc_url.contains(placeholder),
                    "foreign_chains.{:?}.providers.{}.rpc_url must include the path placeholder",
                    chain,
                    provider_name
                );
                Ok(())
            }
            AuthConfig::Query { name, .. } => {
                anyhow::ensure!(
                    !name.trim().is_empty(),
                    "foreign_chains.{:?}.providers.{}.auth.name must be non-empty",
                    chain,
                    provider_name
                );
                Ok(())
            }
        }
    }

    pub fn api_variant_for_chain(
        &self,
        chain: ForeignChainName,
    ) -> anyhow::Result<ChainApiVariant> {
        let raw = self.api_variant.trim();
        anyhow::ensure!(!raw.is_empty(), "api_variant must be non-empty");
        let normalized = raw.to_ascii_lowercase().replace('_', "-");
        ChainApiVariant::parse(chain, &normalized).ok_or_else(|| {
            anyhow::anyhow!("unsupported api_variant {normalized} for chain {chain:?}")
        })
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
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
"#;

        // When
        let config: ConfigFile = serde_yaml::from_str(yaml)?;

        // Then
        config.validate()?;
        assert!(config.foreign_chains.solana.is_some());
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
        let config: ConfigFile = serde_yaml::from_str(yaml).expect("config should parse");
        let result = config.validate();

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
