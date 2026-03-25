use std::{fmt, net::SocketAddr, str::FromStr};

use near_account_id::AccountId;

/// A network address that can be either an IP:port or a hostname:port.
///
/// This type is used for CLI arguments where users may specify either an IP address
/// or a domain name. DNS resolution is deferred to connection time.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeAddress {
    Ip(SocketAddr),
    Host(String, u16),
}

impl FromStr for NodeAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(NodeAddress::Ip(addr));
        }
        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("expected host:port, got '{s}'"))?;
        if host.is_empty() {
            return Err(format!("empty hostname in '{s}'"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in '{s}'"))?;
        Ok(NodeAddress::Host(host.to_string(), port))
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeAddress::Ip(addr) => write!(f, "{addr}"),
            NodeAddress::Host(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// Home directory for storing backup service secrets and configuration.
    #[arg(long, env("BACKUP_HOME_DIR"))]
    pub home_dir: String,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Generate new backup service keys (p2p_private_key and near_signer_key) and save to secrets.json.
    GenerateKeys(GenerateKeysArgs),
    /// Print the NEAR CLI command to register the backup service on the MPC contract.
    Register(RegisterArgs),
    /// Get keyshares from an MPC node and save them locally.
    GetKeyshares(GetKeysharesArgs),
    /// Put keyshares to an MPC node from local storage.
    PutKeyshares(PutKeysharesArgs),
}

#[derive(clap::Args, Debug)]
pub struct GenerateKeysArgs {}

#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    /// MPC contract account ID.
    #[arg(long, env)]
    pub mpc_contract_account_id: AccountId,

    /// NEAR network config name (e.g., testnet, mainnet, mpc-localnet).
    /// This will be used directly in the NEAR CLI command.
    #[arg(long, env)]
    pub near_network: String,

    /// Named account that will sign the registration transaction (e.g., sam.test.near).
    /// This is the operator's account that has permission to register backup services.
    #[arg(long, env)]
    pub signer_account_id: AccountId,
}

#[derive(clap::Args, Debug)]
pub struct GetKeysharesArgs {
    /// host address of the MPC node to retrieve keyshares from (`host:port`).
    #[arg(long, env)]
    pub mpc_node_address: NodeAddress,
    /// P2P public key of the MPC node for authentication.
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
    /// hex encryption key
    #[arg(long, env)]
    pub backup_encryption_key_hex: String,
}

#[derive(clap::Args, Debug)]
pub struct PutKeysharesArgs {
    /// host address of the MPC node to retrieve keyshares from (`host:port`).
    #[arg(long, env)]
    pub mpc_node_address: NodeAddress,
    /// P2P public key of the MPC node for authentication.
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
    /// hex encryption key
    #[arg(long, env)]
    pub backup_encryption_key_hex: String,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use std::net::SocketAddrV4;

    use super::*;

    #[test]
    fn test_parse_ip_address() {
        let addr: NodeAddress = "127.0.0.1:8081".parse().unwrap();
        assert_eq!(
            addr,
            NodeAddress::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8081)))
        );
    }

    #[test]
    fn test_parse_hostname() {
        let addr: NodeAddress = "multichain-testnet-0.nearone.org:8081".parse().unwrap();
        assert_eq!(
            addr,
            NodeAddress::Host("multichain-testnet-0.nearone.org".to_string(), 8081)
        );
    }

    #[test]
    fn test_parse_missing_port() {
        assert!("hostname-only".parse::<NodeAddress>().is_err());
    }

    #[test]
    fn test_parse_empty_host() {
        assert!(":8081".parse::<NodeAddress>().is_err());
    }

    #[test]
    fn test_parse_invalid_port() {
        assert!("host:notaport".parse::<NodeAddress>().is_err());
    }
}
