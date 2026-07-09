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
    pub arbitrum: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hyper_evm: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polygon: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aptos: Option<ForeignChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sui: Option<ForeignChainConfig>,
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

    fn validate_auth_config(&self, chain: dtos::ForeignChain) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url)?;

        // Sui is reached over gRPC, which carries credentials in request metadata; a token
        // substituted into the URL path or query would never be sent.
        if chain == dtos::ForeignChain::Sui {
            anyhow::ensure!(
                matches!(self.auth, AuthConfig::None | AuthConfig::Header { .. }),
                "path or query auth is not supported: gRPC providers support only header auth",
            );
        }
        Ok(())
    }
}

impl ForeignChainsConfig {
    pub fn is_empty(&self) -> bool {
        self.all_configured_chains().is_empty()
    }

    /// Iterate over every chain that has a local config, paired with its DTO identifier.
    pub fn iter_chains(
        &self,
    ) -> impl Iterator<Item = (dtos::ForeignChain, &ForeignChainConfig)> + '_ {
        self.all_configured_chains()
            .into_iter()
            .map(|(cfg, id)| (id, cfg))
    }

    #[expect(deprecated, reason = "https://github.com/near/mpc/issues/3079")]
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

        for (foreign_chain_config, identifier) in configured_chains {
            for (provider_name, provider) in foreign_chain_config.providers.iter() {
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

                // valid auth configuration for the chain's transport
                provider.validate_auth_config(identifier).with_context(|| {
                    format!("provider `{}` has invalid auth", provider_name.as_str())
                })?;
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
            (self.arbitrum.as_ref(), dtos::ForeignChain::Arbitrum),
            (self.hyper_evm.as_ref(), dtos::ForeignChain::HyperEvm),
            (self.polygon.as_ref(), dtos::ForeignChain::Polygon),
            (self.aptos.as_ref(), dtos::ForeignChain::Aptos),
            (self.sui.as_ref(), dtos::ForeignChain::Sui),
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
    fn config_parsing__should_succeed_when_foreign_chain_key_is_unknown() {
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
  not_a_real_chain:
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
        result.expect("unknown foreign chain keys should be silently ignored");
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

    #[test]
    fn config_parsing__should_succeed_with_aptos_section() {
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
  aptos:
    timeout_sec: 30
    max_retries: 3
    providers:
      nodereal:
        rpc_url: "https://aptos-mainnet.nodereal.io/v1/"
        auth:
          kind: none
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with aptos section should be valid");
        assert!(config.foreign_chains.aptos.is_some());
    }

    #[test]
    fn config_parsing__should_succeed_with_aptos_auth_providers() {
        // Given — one provider with the API key in the URL path (Alchemy-style) and one
        // with a header token (NOWNodes-style).
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
  aptos:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        rpc_url: "https://aptos-mainnet.g.alchemy.com/v2/{api_key}/v1"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "alchemy-secret"
      nownodes:
        rpc_url: "https://aptos.nownodes.io/v1"
        auth:
          kind: header
          name: api-key
          token:
            val: "nownodes-secret"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with authenticated aptos providers should be valid");
        let aptos = config
            .foreign_chains
            .aptos
            .as_ref()
            .expect("aptos config should be present");
        assert_eq!(aptos.providers.len(), 2);
    }

    #[test]
    fn config_parsing__should_succeed_with_sui_section() {
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
  sui:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        rpc_url: "https://fullnode.mainnet.sui.io"
        auth:
          kind: none
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with sui section should be valid");
        assert!(config.foreign_chains.sui.is_some());
    }

    #[test]
    fn config_parsing__should_succeed_with_sui_auth_providers() {
        // Given — gRPC providers authenticate via headers; one bearer token and one API key.
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
  sui:
    timeout_sec: 30
    max_retries: 3
    providers:
      blockdaemon:
        rpc_url: "https://svc.blockdaemon.com"
        auth:
          kind: header
          name: Authorization
          scheme: Bearer
          token:
            val: "blockdaemon-secret"
      nownodes:
        rpc_url: "https://sui.nownodes.io"
        auth:
          kind: header
          name: api-key
          token:
            val: "nownodes-secret"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");

        // Then
        config
            .validate()
            .expect("config with authenticated sui providers should be valid");
        let sui = config
            .foreign_chains
            .sui
            .as_ref()
            .expect("sui config should be present");
        assert_eq!(sui.providers.len(), 2);
    }

    #[test]
    fn config_validation__should_reject_sui_provider_with_path_auth() {
        // Given — path auth substitutes the token into the URL, which gRPC never sends.
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
  sui:
    timeout_sec: 30
    max_retries: 3
    providers:
      keyinpath:
        rpc_url: "https://sui.example.com/{api_key}"
        auth:
          kind: path
          placeholder: "{api_key}"
          token:
            val: "secret"
"#;

        // When
        let config: ConfigFile =
            serde_yaml::from_str(yaml).expect("yaml fixture should be correct");
        let result = config.validate();

        // Then — the full error chain names the offending provider and the transport rule.
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("provider `keyinpath`"), "{error}");
        assert!(error.contains("support only header auth"), "{error}");
    }
}
