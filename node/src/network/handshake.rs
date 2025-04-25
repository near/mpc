use crate::asset_queues::types::SerialNumber;
use crate::protocol_version::MPC_PROTOCOL_VERSION;
use borsh::{BorshDeserialize, BorshSerialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTE: u8 = 0xcc;

/// Data about each participant that needs to be shared with every other participant upon
/// connecting.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeDataForNetwork {
    pub db_serial_number: SerialNumber,
}

#[cfg(test)]
impl NodeDataForNetwork {
    pub fn test(seed: u32) -> Self {
        Self {
            db_serial_number: SerialNumber::hash_bytes(&seed.to_be_bytes()),
        }
    }
}

/// Performs a p2p handshake with the other side of the connection; this is done the first thing
/// for each connection. Fails if the handshake result is unexpected.
pub async fn p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
    node_data: &NodeDataForNetwork,
    timeout: std::time::Duration,
) -> anyhow::Result<NodeDataForNetwork> {
    tokio::time::timeout(timeout, async move {
        let mut header = [0u8; 5];
        header[0] = MAGIC_BYTE;
        header[1..].copy_from_slice(&MPC_PROTOCOL_VERSION.to_be_bytes());
        conn.write_all(&header).await?;

        let node_data_buf = borsh::to_vec(node_data).unwrap();
        conn.write_all(&node_data_buf.len().to_be_bytes()).await?;
        conn.write_all(&node_data_buf).await?;

        let mut other_header = [0u8; 5];
        conn.read_exact(&mut other_header).await?;
        if other_header[0] != MAGIC_BYTE {
            anyhow::bail!("Invalid magic byte in handshake");
        }

        let other_protocol_version = u32::from_be_bytes(other_header[1..].try_into().unwrap());
        if other_protocol_version != MPC_PROTOCOL_VERSION {
            anyhow::bail!(
                "Incompatible protocol version; we have {}, they have {}",
                MPC_PROTOCOL_VERSION,
                other_protocol_version
            );
        }

        let mut node_data_buf_len = [0u8; 4];
        conn.read_exact(&mut node_data_buf_len).await?;
        let node_data_buf_len = u32::from_be_bytes(node_data_buf_len);
        let mut node_data_buf = vec![0u8; node_data_buf_len as usize];
        conn.read_exact(&mut node_data_buf).await?;
        let other_handshake_data: NodeDataForNetwork =
            borsh::BorshDeserialize::deserialize(&mut &node_data_buf[..])?;

        anyhow::Ok(other_handshake_data)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::{p2p_handshake, NodeDataForNetwork};
    use crate::asset_queues::types::SerialNumber;
    use crate::network::handshake::MAGIC_BYTE;
    use crate::protocol_version::MPC_PROTOCOL_VERSION;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    fn do_handshake(
        mut a: tokio::io::DuplexStream,
        our_data: &NodeDataForNetwork,
    ) -> impl Future<Output = anyhow::Result<NodeDataForNetwork>> {
        let our_data = our_data.clone();
        let handle = tokio::spawn(async move { p2p_handshake(&mut a, &our_data, TIMEOUT).await });
        async move { handle.await? }
    }

    fn random_node_data() -> NodeDataForNetwork {
        NodeDataForNetwork::test(rand::random())
    }

    #[tokio::test]
    async fn test_p2p_handshake_same_version() {
        let (a, b) = tokio::io::duplex(1024);
        let (a_data, b_data) = (random_node_data(), random_node_data());
        let a_result = do_handshake(a, &a_data);
        let b_result = do_handshake(b, &b_data);
        assert_eq!(a_result.await.unwrap(), b_data);
        assert_eq!(b_result.await.unwrap(), a_data);
    }

    #[tokio::test]
    async fn test_p2p_handshake_different_version() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a, &random_node_data());
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        buf[1..].copy_from_slice(&(MPC_PROTOCOL_VERSION + 1).to_be_bytes());
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Incompatible protocol version; we have {}, they have {}",
                MPC_PROTOCOL_VERSION,
                MPC_PROTOCOL_VERSION + 1
            )
        );
    }

    #[tokio::test]
    async fn test_p2p_handshake_invalid_magic_byte() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a, &random_node_data());
        let buf = [0u8; 10];
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(err.to_string(), "Invalid magic byte in handshake");
    }

    #[tokio::test]
    async fn test_p2p_handshake_response_too_short_and_hangs() {
        for i in 0..=4 {
            let (a, mut b) = tokio::io::duplex(1024);
            let a_result = do_handshake(a, &random_node_data());
            let buf = vec![MAGIC_BYTE; i];
            b.write_all(&buf).await.unwrap();
            let err = a_result.await.unwrap_err();
            assert_eq!(err.to_string(), "deadline has elapsed");
        }
    }
}
