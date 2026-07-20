//! Network identifier for selecting golden reference transactions. Reference
//! transactions are network-specific (a mainnet transaction does not exist on
//! testnet and vice versa).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            other => Err(format!(
                "unknown network `{other}`, expected `mainnet` or `testnet`"
            )),
        }
    }
}
