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
// TODO(#3002): only keep variants that are actually supported by the node binary
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ton: Option<ForeignChainConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignChainConfig {
    pub timeout_sec: NonZeroU64,
    pub max_retries: NonZeroU64,
    pub providers: NonEmptyBTreeMap<RpcProviderName, ForeignChainProviderConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignChainProviderConfig {
    pub rpc_url: String,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    derive_more::Into,
    derive_more::From,
    derive_more::Deref,
)]
pub struct RpcProviderName(String);

impl ForeignChainProviderConfig {
    fn rpc_url(&self) -> Cow<'_, str> {
        self.auth.strip_placeholder(&self.rpc_url)
    }

    fn validate_auth_config(&self) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url)
    }
}

impl ForeignChainsConfig {
    pub fn is_empty(&self) -> bool {
        self.all_configured_chains().is_empty()
    }

    pub fn configured_chains(&self) -> dtos::ForeignChainConfiguration {
        self.all_configured_chains()
            .into_iter()
            .map(|(config, foreign_chain_identifier)| {
                let rpc_providers =
                    config
                        .providers
                        .map_to_set(|_provider_name, provider_config| dtos::RpcProvider {
                            rpc_url: provider_config.rpc_url().trim().to_string(),
                        });

                (foreign_chain_identifier, rpc_providers)
            })
            .collect::<BTreeMap<dtos::ForeignChain, NonEmptyBTreeSet<dtos::RpcProvider>>>()
            .into()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let configured_chains = self.all_configured_chains();

        let mut seen_rpc_urls = BTreeSet::new();

        for (foreign_chain_config, _identifier) in configured_chains {
            for provider in foreign_chain_config.providers.values() {
                let rpc_url = &provider.rpc_url;

                // is a valid URL
                url::Url::parse(rpc_url)
                    .with_context(|| format!("provided RPC URL is invalid: `{rpc_url}`"))?;

                // no duplication
                anyhow::ensure!(
                    seen_rpc_urls.insert(provider.rpc_url.clone()),
                    "found a duplicate URL entry for an RPC provider. RPC provider URLs must be unique across configuration of all chains. {:?}",
                    rpc_url
                );

                // valid auth configuration
                provider.validate_auth_config()?;
            }
        }

        Ok(())
    }

    fn all_configured_chains(&self) -> Vec<(&ForeignChainConfig, dtos::ForeignChain)> {
        [
            (self.solana.as_ref(), dtos::ForeignChain::Solana),
            (self.bitcoin.as_ref(), dtos::ForeignChain::Bitcoin),
            (self.ethereum.as_ref(), dtos::ForeignChain::Ethereum),
            (self.abstract_chain.as_ref(), dtos::ForeignChain::Abstract),
            (self.starknet.as_ref(), dtos::ForeignChain::Starknet),
            (self.bnb.as_ref(), dtos::ForeignChain::Bnb),
            (self.base.as_ref(), dtos::ForeignChain::Base),
            (self.ton.as_ref(), dtos::ForeignChain::Ton),
        ]
        .into_iter()
        .filter_map(|(config, dto_identifier)| config.map(|config| (config, dto_identifier)))
        .collect()
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
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            env: ALCHEMY_API_KEY
      quicknode:
        rpc_url: "https://your-endpoint.solana-mainnet.quiknode.pro/"
        auth:
          kind: header
          name: x-api-key
          token:
            val: "local"
      ankr:
        rpc_url: "https://rpc.ankr.com/near/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            env: ANKR_API_KEY
      public:
        rpc_url: "https://rpc.public.example.com"
        auth:
          kind: none
      query:
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
        rpc_url: "https://blockstream.info/api"
        auth:
          kind: none
  ethereum:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
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
    fn configured_chains__should_strip_path_auth_placeholder_from_rpc_url() {
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
        let configured = config.foreign_chains.configured_chains();

        // Then
        let solana_providers = configured
            .get(&near_mpc_contract_interface::types::ForeignChain::Solana)
            .expect("Solana should be in the configured chains");
        let provider = solana_providers
            .iter()
            .next()
            .expect("expected at least one Solana provider");
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
    fn configured_chains__should_preserve_url_for_non_path_auth() {
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
        let configured = config.foreign_chains.configured_chains();

        // Then
        let eth_providers = configured
            .get(&near_mpc_contract_interface::types::ForeignChain::Ethereum)
            .expect("Ethereum should be in the configured chains");
        let provider = eth_providers
            .iter()
            .next()
            .expect("expected at least one Ethereum provider");
        assert_eq!(provider.rpc_url, "https://eth-mainnet.g.alchemy.com/v2/");

        assert!(
            !configured.contains_key(&near_mpc_contract_interface::types::ForeignChain::Solana)
        );
        assert!(
            !configured.contains_key(&near_mpc_contract_interface::types::ForeignChain::Bitcoin)
        );
    }

    #[test]
    fn config_parsing__should_succeed_with_ton_section() {
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
  ton:
    timeout_sec: 30
    max_retries: 3
    providers:
      toncenter:
        rpc_url: "https://toncenter.com/api/v3/"
        auth:
          kind: header
          name: X-API-Key
          token:
            val: "local-test-key"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with ton section should be valid");
        assert!(config.foreign_chains.ton.is_some());
    }

    #[test]
    fn config_parsing__should_succeed_with_legacy_field__api_variant() {
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
        api_variant: "THIS IS A LEGACY FIELD BEING TESTED"
        rpc_url: "https://starknet-mainnet.blastapi.io/"
        auth:
          kind: none
"#;

        // When/then
        let _config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml serialization passes with `api_variant_field`");
    }
}
