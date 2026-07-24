//! Per-network reference identities (chain ids, genesis hashes) a provider must
//! report. Mainnet and testnet identities differ, so the vectors are
//! network-specific; `None` means the chain is skipped.

use anyhow::Context;

use crate::network::Network;

/// A chain-identity reference: a constant the provider must report for its network,
/// interpreted per chain — an EVM numeric `eth_chainId` (e.g. `8453`), a Starknet
/// short-string felt (e.g. `0x534e5f4d41494e` = `SN_MAIN`; decode the hex as ASCII to
/// verify), an Aptos numeric ledger chain id (1 = mainnet, 2 = testnet), a Bitcoin genesis
/// block hash, or the base58 Sui genesis checkpoint digest. See the `check_*` functions in
/// [`crate::checks`].
#[derive(Clone, Copy)]
pub struct IdentityVector {
    pub identity: &'static str,
}

pub struct GoldenSet {
    pub base: Option<IdentityVector>,
    pub bnb: Option<IdentityVector>,
    pub arbitrum: Option<IdentityVector>,
    pub polygon: Option<IdentityVector>,
    pub hyper_evm: Option<IdentityVector>,
    pub abstract_chain: Option<IdentityVector>,
    pub bitcoin: Option<IdentityVector>,
    pub starknet: Option<IdentityVector>,
    pub aptos: Option<IdentityVector>,
    pub sui: Option<IdentityVector>,
}

pub fn golden_set(network: Network) -> GoldenSet {
    match network {
        Network::Mainnet => MAINNET,
        Network::Testnet => TESTNET,
    }
}

const MAINNET: GoldenSet = GoldenSet {
    // EVM chain ids (decimal), verified against each chain's public RPC via `eth_chainId`
    // (2026-07-24), including `hyper_evm` and `abstract`.
    base: Some(IdentityVector { identity: "8453" }),
    bnb: Some(IdentityVector { identity: "56" }),
    arbitrum: Some(IdentityVector { identity: "42161" }),
    polygon: Some(IdentityVector { identity: "137" }),
    hyper_evm: Some(IdentityVector { identity: "999" }),
    abstract_chain: Some(IdentityVector { identity: "2741" }),
    // Bitcoin genesis block hash (getblockhash 0), never pruned. Well-known constant.
    bitcoin: Some(IdentityVector {
        identity: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    }),
    starknet: Some(IdentityVector {
        identity: "0x534e5f4d41494e",
    }),
    // Aptos ledger chain id: 1 = mainnet.
    aptos: Some(IdentityVector { identity: "1" }),
    // Sui genesis checkpoint digest, exactly as `get_service_info` returns it. Its 4-byte
    // prefix is the well-known Sui chain identifier (mainnet 0x35834a8a, testnet 0x4c78adac),
    // the value to grep against Sui docs to verify these.
    sui: Some(IdentityVector {
        identity: "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
    }),
};

const TESTNET: GoldenSet = GoldenSet {
    base: None,
    bnb: None,
    arbitrum: None,
    polygon: None,
    hyper_evm: None,
    abstract_chain: Some(IdentityVector { identity: "11124" }),
    // Bitcoin testnet3 genesis block hash. Verify if the node targets a different testnet.
    bitcoin: Some(IdentityVector {
        identity: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
    }),
    starknet: Some(IdentityVector {
        identity: "0x534e5f5345504f4c4941",
    }),
    // Aptos ledger chain id: 2 = testnet.
    aptos: Some(IdentityVector { identity: "2" }),
    sui: Some(IdentityVector {
        identity: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
    }),
};

/// Decode a 32-byte hash from hex, tolerating an optional `0x` prefix.
pub fn hex32(hex: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).with_context(|| format!("invalid hex: {hex}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}: {hex}", b.len()))
}

/// Parse an EVM chain id, accepting decimal (`8453`) or `0x`-hex (`0x2105`).
pub fn chain_id_u64(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(hex) => {
            u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex chain id: {s}"))
        }
        None => s.parse().with_context(|| format!("invalid chain id: {s}")),
    }
}

/// Decode a Starknet felt (`0x`-prefixed, possibly fewer than 64 hex digits) into
/// a left-zero-padded 32-byte array.
pub fn felt32(felt: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = felt.strip_prefix("0x").unwrap_or(felt);
    anyhow::ensure!(stripped.len() <= 64, "felt too long: {felt}");
    hex32(&format!("{stripped:0>64}"))
}

/// Decode a base58-encoded 32-byte digest (the form Sui APIs use).
pub fn base58_32(digest: &str) -> anyhow::Result<[u8; 32]> {
    // 32 bytes encode to at most 44 base58 characters; rejecting longer inputs up front
    // also bounds `bs58`'s superlinear decode.
    anyhow::ensure!(
        digest.len() <= 44,
        "base58 digest too long: {} characters",
        digest.len()
    );
    let bytes = bs58::decode(digest)
        .into_vec()
        .with_context(|| format!("invalid base58: {digest}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}: {digest}", b.len()))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn hex32__should_decode_with_and_without_prefix() {
        // Given / When / Then
        hex32("00").unwrap_err();
        assert_eq!(
            hex32("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap()
                [31],
            1
        );
    }

    #[test]
    fn felt32__should_left_pad_short_felts() {
        // Given
        let felt = "0x1";

        // When
        let bytes = felt32(felt).unwrap();

        // Then
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[..31], [0u8; 31]);
    }

    #[test]
    fn golden_sets__should_all_parse() {
        // Given / When / Then
        for network in [Network::Mainnet, Network::Testnet] {
            let set = golden_set(network);
            if let Some(v) = set.bitcoin {
                hex32(v.identity).unwrap();
            }
            for v in [
                set.base,
                set.bnb,
                set.arbitrum,
                set.polygon,
                set.hyper_evm,
                set.abstract_chain,
            ]
            .into_iter()
            .flatten()
            {
                chain_id_u64(v.identity).unwrap();
            }
            if let Some(v) = set.starknet {
                felt32(v.identity).unwrap();
            }
            if let Some(v) = set.aptos {
                chain_id_u64(v.identity).unwrap();
            }
            if let Some(v) = set.sui {
                base58_32(v.identity).unwrap();
            }
        }
    }

    #[test]
    fn base58_32__should_decode_sui_digest() {
        // Given
        let digest = "8eBMXpC8Np7RNDwwiGwSmeev1cSoc7w3fPXdikhH7RZo";

        // When
        let bytes = base58_32(digest).unwrap();

        // Then
        assert_eq!(
            hex::encode(bytes),
            "7188017648e8e95bfa6c0591988f3c7a6ec6caf3967e294f70d906a376d5e4fe"
        );
    }

    #[test]
    fn base58_32__should_reject_invalid_input() {
        // Contains characters outside the base58 alphabet (`0`, `O`, `I`, `l`): decode fails.
        base58_32("not-base58-0OIl").unwrap_err();
        // Valid base58, but decodes to fewer than 32 bytes.
        base58_32("abc").unwrap_err();
        // Longer than any 32-byte digest's base58 (max 44 chars); rejected on length up front,
        // before decoding, since `bs58`'s decode is superlinear in the input length.
        base58_32(&"1".repeat(45)).unwrap_err();
    }
}
