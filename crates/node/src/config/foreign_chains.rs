use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use contract_interface::types as dtos;
use serde::{Deserialize, Serialize};

mod auth;
mod bitcoin;
mod ethereum;
mod solana;

pub use auth::{AuthConfig, TokenConfig};
pub use bitcoin::{BitcoinApiVariant, BitcoinChainConfig, BitcoinProviderConfig};
pub use ethereum::{EthereumApiVariant, EthereumChainConfig, EthereumProviderConfig};
pub use solana::{SolanaApiVariant, SolanaChainConfig, SolanaProviderConfig};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

    pub fn to_policy(&self) -> Option<dtos::ForeignChainPolicy> {
        if self.is_empty() {
            return None;
        }

        let mut chains = BTreeSet::new();

        if let Some(config) = &self.solana {
            chains.insert(dtos::ForeignChainConfig {
                chain: dtos::ForeignChain::Solana,
                providers: providers_to_set(&config.providers),
            });
        }

        if let Some(config) = &self.bitcoin {
            chains.insert(dtos::ForeignChainConfig {
                chain: dtos::ForeignChain::Bitcoin,
                providers: providers_to_set(&config.providers),
            });
        }

        if let Some(config) = &self.ethereum {
            chains.insert(dtos::ForeignChainConfig {
                chain: dtos::ForeignChain::Ethereum,
                providers: providers_to_set(&config.providers),
            });
        }

        Some(dtos::ForeignChainPolicy { chains })
    }
}

fn providers_to_set<P: ForeignChainProviderConfig>(
    providers: &BTreeMap<String, P>,
) -> BTreeSet<dtos::RpcProvider> {
    providers
        .values()
        .map(|provider| dtos::RpcProvider {
            rpc_url: provider.rpc_url().trim().to_string(),
        })
        .collect()
}

pub(crate) trait ForeignChainProviderConfig {
    fn rpc_url(&self) -> Cow<'_, str>;
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()>;
}

pub(crate) fn validate_chain_config<P: ForeignChainProviderConfig>(
    chain_label: &str,
    timeout_sec: u64,
    max_retries: u64,
    providers: &BTreeMap<String, P>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        timeout_sec > 0,
        "foreign_chains.{chain_label}.timeout_sec must be > 0"
    );
    anyhow::ensure!(
        max_retries > 0,
        "foreign_chains.{chain_label}.max_retries must be > 0"
    );
    anyhow::ensure!(
        !providers.is_empty(),
        "foreign_chains.{chain_label} must include at least one provider"
    );

    let mut seen_rpc_urls = BTreeSet::new();
    for (provider_name, provider) in providers {
        let provider_rpc_url = provider.rpc_url();
        anyhow::ensure!(
            !provider_rpc_url.trim().is_empty(),
            "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url must be non-empty"
        );
        url::Url::parse(&provider_rpc_url).with_context(|| {
            format!(
                "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url is not a valid URL"
            )
        })?;
        anyhow::ensure!(
            seen_rpc_urls.insert(provider_rpc_url.to_string()),
            "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url duplicates another provider URL"
        );
        provider
            .validate(chain_label, provider_name)
            .with_context(|| format!("invalid provider {provider_name} for {chain_label}"))?;
    }

    Ok(())
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
        result.unwrap_err();
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
        result.unwrap_err();
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
        result.unwrap_err();
    }

    #[test]
    fn config_parsing__should_fail_when_max_retries_is_zero_for_solana() {
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
    max_retries: 0
    providers:
      public:
        api_variant: standard
        rpc_url: "https://rpc.public.example.com"
        auth:
          kind: none
"#;

        // When
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();

        // Then
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("max_retries must be > 0"));
    }

    #[test]
    fn config_parsing__should_fail_when_max_retries_is_zero_for_bitcoin() {
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
  bitcoin:
    timeout_sec: 30
    max_retries: 0
    providers:
      public:
        api_variant: esplora
        rpc_url: "https://blockstream.info/api"
        auth:
          kind: none
"#;

        // When
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();

        // Then
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("max_retries must be > 0"));
    }

    #[test]
    fn config_parsing__should_fail_when_max_retries_is_zero_for_ethereum() {
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
  ethereum:
    timeout_sec: 30
    max_retries: 0
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
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();

        // Then
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("max_retries must be > 0"));
    }

    #[test]
    fn to_policy__strips_path_auth_placeholder_from_rpc_url() {
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
      ankr:
        api_variant: ankr
        rpc_url: "https://rpc.ankr.com/solana/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "secret"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");
        config.validate().expect("config should be valid");
        let policy = config.foreign_chains.to_policy().unwrap();

        // Then
        let solana_chain = policy
            .chains
            .iter()
            .find(|c| c.chain == contract_interface::types::ForeignChain::Solana)
            .unwrap();
        let provider = solana_chain.providers.iter().next().unwrap();
        assert_eq!(provider.rpc_url, "https://rpc.ankr.com/solana/");
    }

    #[test]
    fn to_policy__preserves_url_for_non_path_auth() {
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
            val: "secret"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");
        config.validate().expect("config should be valid");
        let policy = config.foreign_chains.to_policy().unwrap();

        // Then
        let eth_chain = policy
            .chains
            .iter()
            .find(|c| c.chain == contract_interface::types::ForeignChain::Ethereum)
            .unwrap();
        let provider = eth_chain.providers.iter().next().unwrap();
        assert_eq!(provider.rpc_url, "https://eth-mainnet.g.alchemy.com/v2/");
    }
}
