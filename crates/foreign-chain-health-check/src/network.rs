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
