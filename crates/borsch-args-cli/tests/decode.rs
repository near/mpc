use borsch_args_cli::cli::Cli;
use borsch_args_cli::types::ArgType;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, Config, ForeignChain, ProposeUpdateArgs, ProviderConfig,
    ProviderId,
};

mod testnet_whitelist_fixture {
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{
        AuthScheme, ChainEntry, ChainRouting, ForeignChain, ProviderConfig, ProviderId,
    };

    fn none(base_url: &str) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn path_auth(base_url: &str, placeholder: &str) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme: AuthScheme::Path {
                placeholder: placeholder.to_string(),
            },
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn header_bearer(base_url: &str, header_name: &str) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme: AuthScheme::Header {
                name: header_name.to_string(),
                scheme: Some("Bearer".to_string()),
            },
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn entry(providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>, quorum: u64) -> ChainEntry {
        ChainEntry { providers, quorum }
    }

    fn id(s: &str) -> ProviderId {
        ProviderId(s.to_string())
    }

    pub fn build() -> NonEmptyBTreeMap<ForeignChain, ChainEntry> {
        let bitcoin = entry(
            NonEmptyBTreeMap::new(
                id("public"),
                none("https://bitcoin-testnet-rpc.publicnode.com"),
            ),
            1,
        );
        let mut abstract_providers = NonEmptyBTreeMap::new(
            id("alchemy"),
            path_auth("https://abstract-testnet.g.alchemy.com/v2/", "{API_KEY}"),
        );
        abstract_providers.insert(id("public"), none("https://api.testnet.abs.xyz"));
        abstract_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
        let abstract_chain = entry(abstract_providers, 3);
        let mut starknet_providers = NonEmptyBTreeMap::new(
            id("alchemy"),
            path_auth(
                "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/",
                "{API_KEY}",
            ),
        );
        starknet_providers.insert(
            id("public"),
            none("https://starknet-sepolia-rpc.publicnode.com"),
        );
        starknet_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
        let starknet = entry(starknet_providers, 3);
        let mut aptos_providers = NonEmptyBTreeMap::new(
            id("alchemy"),
            path_auth("https://aptos-testnet.g.alchemy.com/v2/", "{API_KEY}"),
        );
        aptos_providers.insert(
            id("geomi"),
            header_bearer("https://api.testnet.aptoslabs.com/v1", "Authorization"),
        );
        aptos_providers.insert(
            id("public"),
            none("https://fullnode.testnet.aptoslabs.com/v1"),
        );
        aptos_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
        let aptos = entry(aptos_providers, 3);
        let mut batch = NonEmptyBTreeMap::new(ForeignChain::Abstract, abstract_chain);
        batch.insert(ForeignChain::Aptos, aptos);
        batch.insert(ForeignChain::Bitcoin, bitcoin);
        batch.insert(ForeignChain::Starknet, starknet);
        batch
    }
}

#[test]
fn wrong_type_fails_to_decode() {
    let bytes = borsh::to_vec(&42u64).unwrap();
    let err = ArgType::ProposeUpdateArgs.decode(&bytes).unwrap_err();
    assert!(err.to_string().contains("failed to decode"));
}

#[test]
fn rejects_trailing_bytes() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tee-verifier/tests/fixtures/verify_quote_args.borsh"
    );
    let mut bytes = std::fs::read(fixture_path).expect("committed fixture must exist");
    bytes.push(0);
    assert!(ArgType::VerifyQuoteArgs.decode(&bytes).is_err());
}

#[test]
fn process_update_args_decodes() {
    let args = ProposeUpdateArgs {
        code: Some(vec![0x00, 0x61, 0x73, 0x6d]),
        config: Some(Config {
            key_event_timeout_blocks: 0,
            tee_upgrade_deadline_duration_seconds: 0,
            contract_upgrade_deposit_tera_gas: 0,
            sign_call_gas_attachment_requirement_tera_gas: 0,
            ckd_call_gas_attachment_requirement_tera_gas: 0,
            return_signature_and_clean_state_on_success_call_tera_gas: 0,
            return_ck_and_clean_state_on_success_call_tera_gas: 0,
            fail_on_timeout_tera_gas: 0,
            fail_attestation_submission_tera_gas: 0,
            clean_tee_status_tera_gas: 0,
            clean_invalid_attestations_tera_gas: 0,
            cleanup_orphaned_node_migrations_tera_gas: 0,
            remove_non_participant_update_votes_tera_gas: 0,
            clean_foreign_chain_data_tera_gas: 0,
            remove_non_participant_tee_verifier_votes_tera_gas: 0,
            verifier_tera_gas: 0,
            resolve_verification_tera_gas: 0,
        }),
    };
    let bytes = borsh::to_vec(&args).unwrap();
    let decoded = ArgType::ProposeUpdateArgs.decode(&bytes).unwrap();
    assert_eq!(decoded["wasmstat"]["valid"], true);
    assert_eq!(decoded["config"]["key_event_timeout_blocks"], 0);
    assert_eq!(decoded["config"]["fail_attestation_submission_tera_gas"], 0);
}

#[test]
fn round_trips_to_json() {
    let provider = ProviderConfig {
        base_url: "https://rpc.example.com".to_string(),
        auth_scheme: AuthScheme::None,
        chain_routing: ChainRouting::Embedded,
    };
    let entry = ChainEntry {
        providers: NonEmptyBTreeMap::new(ProviderId("example".to_string()), provider),
        quorum: 1,
    };
    let votes = NonEmptyBTreeMap::new(ForeignChain::Bitcoin, entry);
    let bytes = borsh::to_vec(&votes).unwrap();
    let decoded = ArgType::ForeignChainProviderVotes.decode(&bytes).unwrap();
    assert_eq!(
        decoded["Bitcoin"]["providers"]["example"]["base_url"],
        "https://rpc.example.com"
    );
    assert_eq!(decoded["Bitcoin"]["quorum"], 1);
}

#[test]
fn decodes_against_localnet_fixture() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tee-verifier/tests/fixtures/verify_quote_args.borsh"
    );
    let bytes = std::fs::read(fixture_path).expect("committed fixture must exist");
    let decoded = ArgType::VerifyQuoteArgs.decode(&bytes).unwrap();
    let [quote, collateral] = decoded.as_array().unwrap().as_slice() else {
        panic!("expected a two-element [quote, collateral] array, got {decoded:?}");
    };
    assert!(!quote.is_null());
    assert!(
        collateral["pck_crl_issuer_chain"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
}

#[test]
fn testnet_whitelist_payload() {
    let batch = testnet_whitelist_fixture::build();
    let bytes = borsh::to_vec(&batch).unwrap();
    assert_eq!(bytes.len(), 709, "payload size changed vs near/mpc#3646");
    let decoded = ArgType::ForeignChainProviderVotes.decode(&bytes).unwrap();
    assert_eq!(decoded["Bitcoin"]["quorum"], 1);
    assert_eq!(decoded["Abstract"]["quorum"], 3);
    assert_eq!(decoded["Starknet"]["quorum"], 3);
    assert_eq!(decoded["Aptos"]["quorum"], 3);
    assert_eq!(
        decoded["Bitcoin"]["providers"]["public"]["base_url"],
        "https://bitcoin-testnet-rpc.publicnode.com"
    );
    assert_eq!(
        decoded["Aptos"]["providers"]["geomi"]["auth_scheme"]["Header"]["name"],
        "Authorization"
    );
    assert_eq!(
        decoded["Aptos"]["providers"]["geomi"]["auth_scheme"]["Header"]["scheme"],
        "Bearer"
    );
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let cli = Cli {
        r#type: ArgType::ForeignChainProviderVotes,
        file: None,
        base64: Some(b64),
    };
    assert_eq!(cli.input_bytes().unwrap(), bytes);
}

// TODO: Exhaustive tests
