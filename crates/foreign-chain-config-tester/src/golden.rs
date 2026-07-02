//! Per-network reference transactions and the value an inspector must extract
//! from each. A mainnet transaction does not exist on testnet (and vice versa),
//! so the vectors are network-specific; `None` means the chain is skipped.

use anyhow::Context;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn label(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

/// Hashes are hex, with or without a `0x` prefix.
#[derive(Clone, Copy)]
pub struct BlockHashVector {
    pub tx: &'static str,
    pub block_hash: &'static str,
}

#[derive(Clone, Copy)]
pub struct AptosVector {
    pub tx: &'static str,
    pub event_type_tag: &'static str,
    pub event_sequence_number: u64,
}

pub struct GoldenSet {
    pub base: Option<BlockHashVector>,
    pub bnb: Option<BlockHashVector>,
    pub arbitrum: Option<BlockHashVector>,
    pub polygon: Option<BlockHashVector>,
    pub hyper_evm: Option<BlockHashVector>,
    pub abstract_chain: Option<BlockHashVector>,
    pub bitcoin: Option<BlockHashVector>,
    pub starknet: Option<BlockHashVector>,
    pub aptos: Option<AptosVector>,
}

pub fn golden_set(network: Network) -> GoldenSet {
    match network {
        Network::Mainnet => MAINNET,
        Network::Testnet => TESTNET,
    }
}

const MAINNET: GoldenSet = GoldenSet {
    base: Some(BlockHashVector {
        tx: "a11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1",
        block_hash: "b8488c9272c547c45e63ea76cc2d1c927c8f888e2721f790b14db996b6cc6aca",
    }),
    bnb: Some(BlockHashVector {
        tx: "90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349",
        block_hash: "4f125b8e2716df5cbc72719212d5189dae0e49b6b7a44523165cb01888914999",
    }),
    arbitrum: Some(BlockHashVector {
        tx: "8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484",
        block_hash: "da0e369bfb9688ca4591604104e4f2953329542bfb3bc0d0c94686b5ad798c1c",
    }),
    polygon: Some(BlockHashVector {
        tx: "7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38",
        block_hash: "56d98f80b91c9cf9dcda71c63c01ea441d46ba31149c902adfbee97e55ff82a6",
    }),
    hyper_evm: Some(BlockHashVector {
        tx: "4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a",
        block_hash: "657b2ee81add87e3f654840425baca06a06d5876f6d2d873197e70f00f6762e6",
    }),
    abstract_chain: Some(BlockHashVector {
        tx: "4572b72d765f07712cf571993fd805888ede9cd05107f65338defee02f7ea755",
        block_hash: "3bb255d468a552a75fc3f4916623b207ceb2d3074dfa14442ac03f0f73423708",
    }),
    bitcoin: Some(BlockHashVector {
        tx: "58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c",
        block_hash: "00000000000000000001fadaf3f8591e071c202762193cf78e389ea691f2ecab",
    }),
    starknet: Some(BlockHashVector {
        tx: "0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e",
        block_hash: "0x1b716b05027567f9f4a2fe37f8769dc3b04a2e5a3893f6e0ed45f24c7c0ffa5",
    }),
    aptos: Some(AptosVector {
        tx: "adc6b85a0931fc7f0d7e3839b52d63105e22cec1cb1cdee48aa2065773098c3c",
        event_type_tag: "0x1::block::NewBlockEvent",
        event_sequence_number: 822_198_006,
    }),
};

const TESTNET: GoldenSet = GoldenSet {
    base: None,
    bnb: None,
    arbitrum: None,
    polygon: None,
    hyper_evm: None,
    abstract_chain: Some(BlockHashVector {
        tx: "497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234",
        block_hash: "4c93dd4a8f347e6480b0a44f8c2b7eecdfb31d711e8d542fd60112ea5d98fb02",
    }),
    bitcoin: Some(BlockHashVector {
        tx: "5acaa0890f8c1f1b2ac114c25b38d376f23beda1b59e9bcba33256d6e11d7e8e",
        block_hash: "000000000000021f43445ab447b3fc85e93eca26b56a4f23ef6c017682038ca2",
    }),
    starknet: Some(BlockHashVector {
        tx: "0x115b24c74eade5ee4c01e63cce5aa462fc2d59d040f5b088a31ad44c9aa58dc",
        block_hash: "0x1f33823b145e92ca069b90d3cfb012277762d9dd1dc2efb975b10a7c3d92875",
    }),
    aptos: Some(AptosVector {
        tx: "b463d73b3a2e9c684caf9b27eb66a147348130c50fc8fa74a3f56e712c942773",
        event_type_tag: "0x1::block::NewBlockEvent",
        event_sequence_number: 302_761_912,
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

/// Decode a Starknet felt (`0x`-prefixed, possibly fewer than 64 hex digits) into
/// a left-zero-padded 32-byte array.
pub fn felt32(felt: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = felt.strip_prefix("0x").unwrap_or(felt);
    anyhow::ensure!(stripped.len() <= 64, "felt too long: {felt}");
    hex32(&format!("{stripped:0>64}"))
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
            for v in [
                set.base,
                set.bnb,
                set.arbitrum,
                set.polygon,
                set.hyper_evm,
                set.abstract_chain,
                set.bitcoin,
            ]
            .into_iter()
            .flatten()
            {
                hex32(v.tx).unwrap();
                hex32(v.block_hash).unwrap();
            }
            if let Some(v) = set.starknet {
                felt32(v.tx).unwrap();
                felt32(v.block_hash).unwrap();
            }
            if let Some(v) = set.aptos {
                hex32(v.tx).unwrap();
            }
        }
    }
}
