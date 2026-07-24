//! Network identifier for selecting reference identities, which are
//! network-specific (a provider on mainnet reports a different chain id /
//! genesis hash than one on testnet).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
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
