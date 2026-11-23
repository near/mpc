use std::path::Path;

use near_indexer::near_primitives::version::PROTOCOL_VERSION;

#[test]
#[expect(non_snake_case)]
fn localnet_genesis__should_match_nearcore_protocol_version() {
    // Given
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deployment/localnet/genesis.json");
    let genesis: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    // When
    let protocol_version = genesis["protocol_version"].as_u64();

    // Then
    assert_eq!(
        protocol_version,
        Some(u64::from(PROTOCOL_VERSION)),
        "set protocol_version in deployment/localnet/genesis.json to {PROTOCOL_VERSION}"
    );
}
