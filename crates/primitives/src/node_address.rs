use alloc::string::{String, ToString};
use core::net::SocketAddr;
use core::str::FromStr;
use thiserror::Error;

/// A node's network address: either an `IP:port` or a `hostname:port`.
///
/// Parsed from a participant's `url` field. A `http://` or `https://` scheme is optional
/// and only used as a hint to default the port when one is omitted (`http` → 80,
/// `https` → 443); the scheme is otherwise discarded, since only host and port are needed
/// to open the P2P TCP connection. DNS resolution of hostnames is deferred to connect time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAddress {
    Ip(SocketAddr),
    Host(String, u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeAddressParseError {
    #[error("expected host:port, got '{0}'")]
    MissingPort(String),
    #[error("empty hostname in '{0}'")]
    EmptyHostname(String),
    #[error("invalid port in '{0}'")]
    InvalidPort(String),
    #[error("unsupported scheme in '{0}'")]
    UnsupportedScheme(String),
}

impl NodeAddress {
    pub fn host(&self) -> String {
        match self {
            NodeAddress::Ip(addr) => addr.ip().to_string(),
            NodeAddress::Host(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            NodeAddress::Ip(addr) => addr.port(),
            NodeAddress::Host(_, port) => *port,
        }
    }
}

impl FromStr for NodeAddress {
    type Err = NodeAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (authority, default_port) = match s.split_once("://") {
            Some(("https", rest)) => (rest, Some(443u16)),
            Some(("http", rest)) => (rest, Some(80u16)),
            Some(_) => return Err(NodeAddressParseError::UnsupportedScheme(s.to_string())),
            None => (s, None),
        };

        // `IP:port`.
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Ok(NodeAddress::Ip(addr));
        }

        // `hostname[:port]`; a missing port falls back to the scheme's default, if any.
        match authority.rsplit_once(':') {
            Some((host, port_str)) => {
                if host.is_empty() {
                    return Err(NodeAddressParseError::EmptyHostname(s.to_string()));
                }
                let port = port_str
                    .parse()
                    .map_err(|_| NodeAddressParseError::InvalidPort(s.to_string()))?;
                Ok(NodeAddress::Host(host.to_string(), port))
            }
            None => {
                if authority.is_empty() {
                    return Err(NodeAddressParseError::EmptyHostname(s.to_string()));
                }
                let port = default_port
                    .ok_or_else(|| NodeAddressParseError::MissingPort(s.to_string()))?;
                Ok(NodeAddress::Host(authority.to_string(), port))
            }
        }
    }
}

impl core::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NodeAddress::Ip(addr) => write!(f, "{addr}"),
            NodeAddress::Host(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn from_str__should_parse_ip_and_port_as_ip_variant() {
        // Given
        let input = "127.0.0.1:8081";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(
            parsed,
            NodeAddress::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8081)))
        );
    }

    #[test]
    fn from_str__should_parse_hostname_and_port_as_host_variant() {
        // Given
        let input = "multichain-testnet-0.nearone.org:8081";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(
            parsed,
            NodeAddress::Host("multichain-testnet-0.nearone.org".to_string(), 8081)
        );
    }

    #[test]
    fn from_str__should_strip_http_scheme_and_keep_explicit_port() {
        // Given
        let input = "http://10.101.0.56:3000";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(parsed.host(), "10.101.0.56");
        assert_eq!(parsed.port(), 3000);
    }

    #[test]
    fn from_str__should_default_port_80_for_http_without_port() {
        // Given
        let input = "http://34.49.211.4";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(parsed.port(), 80);
    }

    #[test]
    fn from_str__should_default_port_443_for_https_without_port() {
        // Given
        let input = "https://node.example.com";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(
            parsed,
            NodeAddress::Host("node.example.com".to_string(), 443)
        );
    }

    #[test]
    fn from_str__should_let_explicit_port_win_over_scheme_default() {
        // Given
        let input = "https://node.example.com:13001";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(
            parsed,
            NodeAddress::Host("node.example.com".to_string(), 13001)
        );
    }

    #[test]
    fn from_str__should_accept_scheme_less_host_port() {
        // Given
        let input = "10.101.0.122:3000";

        // When
        let parsed: NodeAddress = input.parse().unwrap();

        // Then
        assert_eq!(parsed.host(), "10.101.0.122");
        assert_eq!(parsed.port(), 3000);
    }

    #[test]
    fn from_str__should_reject_empty_host() {
        // Given
        let input = "http://:3000";

        // When
        let parsed = input.parse::<NodeAddress>();

        // Then
        assert_eq!(
            parsed,
            Err(NodeAddressParseError::EmptyHostname(input.to_string()))
        );
    }

    #[test]
    fn from_str__should_reject_scheme_less_host_without_port() {
        // Given
        let input = "hostname-only";

        // When
        let parsed = input.parse::<NodeAddress>();

        // Then
        assert_eq!(
            parsed,
            Err(NodeAddressParseError::MissingPort(input.to_string()))
        );
    }

    #[test]
    fn from_str__should_reject_non_numeric_port() {
        // Given
        let input = "host:notaport";

        // When
        let parsed = input.parse::<NodeAddress>();

        // Then
        assert_eq!(
            parsed,
            Err(NodeAddressParseError::InvalidPort(input.to_string()))
        );
    }

    #[test]
    fn from_str__should_reject_unsupported_scheme() {
        // Given
        let input = "ftp://node.example.com:21";

        // When
        let parsed = input.parse::<NodeAddress>();

        // Then
        assert_eq!(
            parsed,
            Err(NodeAddressParseError::UnsupportedScheme(input.to_string()))
        );
    }

    #[test]
    fn display__should_round_trip_hostname() {
        // Given
        let parsed: NodeAddress = "http://node.example.com:3000".parse().unwrap();

        // When
        let rendered = parsed.to_string();

        // Then
        assert_eq!(rendered, "node.example.com:3000");
    }
}
