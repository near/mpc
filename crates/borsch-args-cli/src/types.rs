use anyhow::{Context, Result};
use borsh::BorshDeserialize;
use dcap_qvl::quote::Quote;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{ChainEntry, ForeignChain, ProposeUpdateArgs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tee_verifier_interface::{Collateral, QuoteBytes};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ArgType {
    /// `propose_update`'s single argument, `ProposeUpdateArgs { code, config }`.
    ProposeUpdateArgs,
    /// `tee-verifier`'s `verify_quote(quote, collateral)`. Two borsh args concatenated back-to-back in the file
    VerifyQuoteArgs,
    /// `vote_update_foreign_chain_providers`'s single argument, a `NonEmptyBTreeMap<ForeignChain, ChainEntry>`.
    ForeignChainProviderVotes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmStat {
    hash: String,
    size: usize,
    valid: bool,
}

impl ArgType {
    pub fn decode(self, bytes: &[u8]) -> Result<Value> {
        match self {
            ArgType::ProposeUpdateArgs => {
                let args = decode::<ProposeUpdateArgs>(bytes)?;
                let code_bytes = args.code.clone();
                if let Some(code_bytes) = code_bytes {
                    let mut hasher = Sha256::new();
                    hasher.update(code_bytes.clone());
                    let full_hex_hash = hex::encode(hasher.finalize());
                    let stat = WasmStat {
                        hash: full_hex_hash,
                        size: code_bytes.len(),
                        valid: code_bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]), // \0asm
                    };
                    return jsonify(
                        &serde_json::json!({"wasmstat": stat,"config": args.config.clone()}),
                    );
                }
                jsonify(&args)
            }
            ArgType::VerifyQuoteArgs => {
                let (quote_bytes, collateral) = decode::<(QuoteBytes, Collateral)>(bytes)?;
                let quote = Quote::parse(&quote_bytes.0).context(
                    "Failed to parse hardware enclave bytes into structured DCAP Quote type",
                )?;
                jsonify(&(quote, collateral))
            }
            ArgType::ForeignChainProviderVotes => jsonify(&decode::<
                NonEmptyBTreeMap<ForeignChain, ChainEntry>,
            >(bytes)?),
        }
    }
}

fn decode<T: BorshDeserialize + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = T::try_from_slice(bytes)
        .with_context(|| format!("failed to decode bytes as {}", std::any::type_name::<T>()))?;
    Ok(value)
}

fn jsonify<T: Serialize>(value: &T) -> Result<Value> {
    let json = serde_json::to_value(value).context("failed to render decoded value as JSON")?;
    Ok(json)
}
