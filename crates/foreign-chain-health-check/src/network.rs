//! Network identifier for selecting golden reference transactions. Reference
//! transactions are network-specific (a mainnet transaction does not exist on
//! testnet and vice versa).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const ALL: &'static [Network] = &[Network::Mainnet, Network::Testnet];

    pub fn label(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }

    fn labels() -> String {
        Self::ALL
            .iter()
            .map(|n| n.label())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("expected one of: {}", Network::labels())]
pub struct ParseNetworkError;

impl std::str::FromStr for Network {
    type Err = ParseNetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|n| n.label() == s)
            .ok_or(ParseNetworkError)
    }
}
