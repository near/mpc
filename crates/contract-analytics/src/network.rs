use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use near_primitives::types::AccountId;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Localnet,
}

impl Network {
    pub fn default_rpc_url(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some("https://rpc.mainnet.near.org"),
            Self::Testnet => Some("https://rpc.testnet.near.org"),
            Self::Localnet => None,
        }
    }

    pub fn default_contract(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some("v1.signer"),
            Self::Testnet => Some("v1.signer-prod.testnet"),
            Self::Localnet => None,
        }
    }
}

pub struct Endpoint {
    pub rpc_url: String,
    pub contract_id: AccountId,
}

pub fn resolve(
    network: Network,
    rpc_url_override: Option<String>,
    contract_override: Option<AccountId>,
) -> Result<Endpoint> {
    let rpc_url = match (rpc_url_override, network.default_rpc_url()) {
        (Some(u), _) => u,
        (None, Some(u)) => u.to_string(),
        (None, None) => bail!("--rpc-url is required for --network localnet"),
    };
    let contract_id = match (contract_override, network.default_contract()) {
        (Some(c), _) => c,
        (None, Some(c)) => c
            .parse()
            .with_context(|| format!("invalid default contract id `{c}`"))?,
        (None, None) => bail!("--contract is required for --network localnet"),
    };
    Ok(Endpoint {
        rpc_url,
        contract_id,
    })
}
