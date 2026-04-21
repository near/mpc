use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroU64;

use anyhow::Context as _;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_mpc_contract_interface::types as dtos;
use serde::{Deserialize, Serialize};

pub use auth::{AuthConfig, TokenConfig};

mod auth;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForeignChainsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ethereum: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "abstract")]
    pub abstract_chain: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starknet: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bnb: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<ForeignChainConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignChainConfig {
    pub timeout_sec: NonZeroU64,
    pub max_retries: NonZeroU64,
    // TODO: what is the key here?
    pub providers: NonEmptyBTreeMap<String, ForeignChainProviderConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]

pub struct ForeignChainProviderConfig {
    pub rpc_url: String,
    pub api_variant: RpcProvider,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

impl ForeignChainsConfig {
    pub fn validate_chain_config(&self) -> anyhow::Result<()> {
        let foreign_chains = [
            self.solana.as_ref(),
            self.bitcoin.as_ref(),
            self.ethereum.as_ref(),
            self.abstract_chain.as_ref(),
            self.starknet.as_ref(),
            self.bnb.as_ref(),
            self.base.as_ref(),
        ];

        let mut seen_rpc_urls = BTreeSet::new();

        for foreign_chain in foreign_chains {
            let Some(foreign_chain) = foreign_chain else {
                continue;
            };

            for provider in foreign_chain.providers.values() {
                let rpc_url = &provider.rpc_url;

                // is a valid URL
                url::Url::parse(&rpc_url)
                    .with_context(|| format!("provided RPC URL is invalid: `{rpc_url}`"))?;

                // no duplication
                anyhow::ensure!(
                    seen_rpc_urls.insert(provider.rpc_url.clone()),
                    "found a duplicate URL entry for an RPC provider. RPC provider URLs must be unique across configuration of all chains. {:?}",
                    rpc_url
                );
            }
        }

        Ok(())
    }
}

impl ForeignChainConfig {
    pub(crate) fn providers_to_set(&self) -> NonEmptyBTreeSet<dtos::RpcProvider> {
        self.providers
            .map_to_set(|_name, provider| dtos::RpcProvider {
                rpc_url: provider.rpc_url.to_string(),
            })
    }
}

impl ForeignChainProviderConfig {
    fn rpc_url(&self) -> Cow<'_, str> {
        self.auth.strip_placeholder(&self.rpc_url)
    }

    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RpcProvider {
    Standard,
    Alchemy,
    Helius,
    Quicknode,
    Ankr,
    Infura,
    Blast,
    #[serde(alias = "blockstream")]
    #[serde(alias = "mempool-space")]
    Esplora,
}

impl ForeignChainsConfig {
    pub fn is_empty(&self) -> bool {
        self.solana.is_none()
            && self.bitcoin.is_none()
            && self.ethereum.is_none()
            && self.abstract_chain.is_none()
            && self.starknet.is_none()
            && self.bnb.is_none()
            && self.base.is_none()
    }

    pub fn to_policy(&self) -> Option<dtos::ForeignChainPolicy> {
        if self.is_empty() {
            return None;
        }

        let mut chains = BTreeMap::new();

        if let Some(config) = &self.solana {
            chains.insert(dtos::ForeignChain::Solana, config.providers_to_set());
        }

        if let Some(config) = &self.bitcoin {
            chains.insert(dtos::ForeignChain::Bitcoin, config.providers_to_set());
        }

        if let Some(config) = &self.ethereum {
            chains.insert(dtos::ForeignChain::Ethereum, config.providers_to_set());
        }

        if let Some(config) = &self.abstract_chain {
            chains.insert(dtos::ForeignChain::Abstract, config.providers_to_set());
        }

        if let Some(config) = &self.starknet {
            chains.insert(dtos::ForeignChain::Starknet, config.providers_to_set());
        }

        if let Some(config) = &self.bnb {
            chains.insert(dtos::ForeignChain::Bnb, config.providers_to_set());
        }

        if let Some(config) = &self.base {
            chains.insert(dtos::ForeignChain::Base, config.providers_to_set());
        }

        Some(dtos::ForeignChainPolicy { chains })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::ConfigFile;

    #[test]
    fn config_parsing__should_succeed_when_foreign_chains_are_unset() {
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
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config without foreign_chains should be valid");
        assert!(config.foreign_chains.is_empty());
    }

    #[test]
    fn config_parsing__should_succeed_when_foreign_chains_are_set() {
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
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with foreign_chains should be valid");
        assert!(config.foreign_chains.solana.is_some());
        assert!(config.foreign_chains.bitcoin.is_some());
        assert!(config.foreign_chains.ethereum.is_some());
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
    fn config_parsing__should_fail_when_api_variant_is_unknown() {
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
        api_variant: not-a-real-provider
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
        let solana_providers = policy
            .chains
            .get(&near_mpc_contract_interface::types::ForeignChain::Solana)
            .unwrap();
        let provider = solana_providers.iter().next().unwrap();
        assert_eq!(provider.rpc_url, "https://rpc.ankr.com/solana/");
    }

    #[test]
    fn config_parsing__should_succeed_with_starknet_section() {
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
  starknet:
    timeout_sec: 30
    max_retries: 3
    providers:
      blast:
        api_variant: blast
        rpc_url: "https://starknet-mainnet.blastapi.io/"
        auth:
          kind: none
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with starknet section should be valid");
        assert!(config.foreign_chains.starknet.is_some());
    }

    #[test]
    fn config_parsing__should_fail_when_max_retries_is_zero_for_starknet() {
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
  starknet:
    timeout_sec: 30
    max_retries: 0
    providers:
      blast:
        api_variant: blast
        rpc_url: "https://starknet-mainnet.blastapi.io/"
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
        let eth_providers = policy
            .chains
            .get(&near_mpc_contract_interface::types::ForeignChain::Ethereum)
            .unwrap();
        let provider = eth_providers.iter().next().unwrap();
        assert_eq!(provider.rpc_url, "https://eth-mainnet.g.alchemy.com/v2/");
    }
}
