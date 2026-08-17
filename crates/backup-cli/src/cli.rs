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

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum NodeAddressParseError {
    #[error("expected host:port, got '{0}'")]
    MissingPort(String),
    #[error("empty hostname in '{0}'")]
    EmptyHostname(String),
    #[error("invalid port in '{0}'")]
    InvalidPort(String),
}

impl FromStr for NodeAddress {
    type Err = NodeAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(NodeAddress::Ip(addr));
        }
        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| NodeAddressParseError::MissingPort(s.to_string()))?;
        if host.is_empty() {
            return Err(NodeAddressParseError::EmptyHostname(s.to_string()));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| NodeAddressParseError::InvalidPort(s.to_string()))?;
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
    GetKeyshares(NodeConnectionArgs),
    /// Put keyshares to an MPC node from local storage.
    PutKeyshares(NodeConnectionArgs),
    /// Run the automatic backup service: watch the MPC contract and back up keyshares whenever
    /// the stored ones no longer cover its keyset.
    Run(RunArgs),
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

/// How to reach an MPC node. Shared by every subcommand that talks to one.
#[derive(clap::Args, Debug)]
pub struct NodeConnectionArgs {
    /// host address of the MPC node to exchange keyshares with (`host:port`).
    #[arg(long, env)]
    pub mpc_node_address: NodeAddress,
    /// P2P public key of the MPC node for authentication.
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
    /// hex encryption key. Prefer passing this via the environment
    /// (`BACKUP_ENCRYPTION_KEY_HEX`) rather than on the command line.
    #[arg(long, env, hide_env_values = true)]
    pub backup_encryption_key_hex: String,
    /// Deadline for a single network request
    #[arg(long, env, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub request_timeout_seconds: u64,
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// NEAR JSON-RPC endpoint used to poll the contract state. A provider api key, if any, is
    /// passed as a query parameter of this URL; only the scheme and host ever reach the logs.
    #[arg(long, env("BACKUP_RPC_URL"), hide_env_values = true)]
    pub rpc_url: String,
    /// NEAR chain id (e.g. mainnet, testnet). Required by the RPC client; the contract state
    /// is read with a view call, which does not consume it.
    #[arg(long, env, default_value = "mainnet")]
    pub near_chain_id: String,
    /// MPC contract account ID whose state is polled.
    #[arg(long, env)]
    pub mpc_contract_account_id: AccountId,
    #[command(flatten)]
    pub node: NodeConnectionArgs,
    /// How often to poll the contract state, in seconds.
    #[arg(long, env, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    pub poll_interval_seconds: u64,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use std::net::SocketAddrV4;

    use clap::{CommandFactory as _, Parser as _};
    use rstest::rstest;

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

    #[rstest]
    #[case::missing_port("hostname-only", NodeAddressParseError::MissingPort("hostname-only".to_string()))]
    #[case::empty_hostname(":8081", NodeAddressParseError::EmptyHostname(":8081".to_string()))]
    #[case::invalid_port("host:notaport", NodeAddressParseError::InvalidPort("host:notaport".to_string()))]
    fn test_parse_errors(#[case] input: &str, #[case] want_err: NodeAddressParseError) {
        let err = input
            .parse::<NodeAddress>()
            .expect_err(&format!("expected error for: {input}"));
        assert_eq!(err, want_err);
    }

    #[rstest]
    #[case::run("run", "BACKUP_ENCRYPTION_KEY_HEX")]
    #[case::run_rpc_url("run", "BACKUP_RPC_URL")]
    #[case::get_keyshares("get-keyshares", "BACKUP_ENCRYPTION_KEY_HEX")]
    #[case::put_keyshares("put-keyshares", "BACKUP_ENCRYPTION_KEY_HEX")]
    fn help__should_not_render_values_of_secret_env_vars(
        #[case] subcommand: &str,
        #[case] env_var: &str,
    ) {
        // Given
        let mut command = Args::command();
        let subcommand = command
            .find_subcommand_mut(subcommand)
            .expect("subcommand should exist");

        // When
        let help = subcommand.render_long_help().to_string();

        // Then
        assert!(
            help.contains(&format!("[env: {env_var}]")),
            "{env_var} should be documented without its value:\n{help}"
        );
        assert!(
            !help.contains(&format!("[env: {env_var}=")),
            "{env_var} value must not be rendered:\n{help}"
        );
    }

    #[rstest]
    #[case::poll_interval("--poll-interval-seconds")]
    #[case::request_timeout("--request-timeout-seconds")]
    fn run_args__should_reject_a_zero_duration(#[case] flag: &str) {
        // Given
        let args = [
            "backup-cli",
            "--home-dir",
            "/tmp/backup",
            "run",
            "--rpc-url",
            "https://rpc.example.com",
            "--mpc-contract-account-id",
            "v1.signer",
            "--mpc-node-address",
            "node.example.com:8079",
            "--mpc-node-p2p-key",
            "ed25519:11111111111111111111111111111111",
            "--backup-encryption-key-hex",
            "00",
            flag,
            "0",
        ];

        // When
        let result = Args::try_parse_from(args);

        // Then
        let err = result.expect_err(&format!("expected {flag} 0 to be rejected"));
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }
}
