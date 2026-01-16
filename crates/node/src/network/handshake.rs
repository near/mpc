use crate::protocol_version::MPC_PROTOCOL_VERSION;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTE: u8 = 0xcc;

/// Performs a p2p handshake with the other side of the connection; this is done the first thing
/// for each connection. Fails if the handshake result is unexpected.
pub async fn p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, async move {
        let mut handshake_buf = [0u8; 5];
        handshake_buf[0] = MAGIC_BYTE;
        handshake_buf[1..].copy_from_slice(&MPC_PROTOCOL_VERSION.to_be_bytes());
        conn.write_all(&handshake_buf).await?;

        let mut other_handshake = [0u8; 5];
        conn.read_exact(&mut other_handshake).await?;
        if other_handshake[0] != MAGIC_BYTE {
            anyhow::bail!("Invalid magic byte in handshake");
        }

        let other_protocol_version = u32::from_be_bytes(other_handshake[1..].try_into().unwrap());
        if other_protocol_version < MPC_PROTOCOL_VERSION {
            anyhow::bail!(
                "Incompatible protocol version; we have {}, they have {}",
                MPC_PROTOCOL_VERSION,
                other_protocol_version
            );
        }
        anyhow::Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::p2p_handshake;
    use crate::network::handshake::MAGIC_BYTE;
    use crate::protocol_version::MPC_PROTOCOL_VERSION;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    fn do_handshake(mut a: tokio::io::DuplexStream) -> impl Future<Output = anyhow::Result<()>> {
        let handle = tokio::spawn(async move { p2p_handshake(&mut a, TIMEOUT).await });
        async move { handle.await? }
    }

    #[tokio::test]
    async fn test_p2p_handshake_same_version() {
        let (a, b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let b_result = do_handshake(b);
        a_result.await.unwrap();
        b_result.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_handshake_accept_higher_version() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        buf[1..].copy_from_slice(&(MPC_PROTOCOL_VERSION + 1).to_be_bytes());
        b.write_all(&buf).await.unwrap();
        a_result.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_handshake_reject_lower_version() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        buf[1..].copy_from_slice(&(MPC_PROTOCOL_VERSION - 1).to_be_bytes());
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Incompatible protocol version; we have {}, they have {}",
                MPC_PROTOCOL_VERSION,
                MPC_PROTOCOL_VERSION - 1
            )
        );
    }

    #[tokio::test]
    async fn test_p2p_handshake_invalid_magic_byte() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let buf = [0u8; 10];
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(err.to_string(), "Invalid magic byte in handshake");
    }

    #[tokio::test]
    async fn test_p2p_handshake_response_too_short_and_hangs() {
        for i in 0..=4 {
            let (a, mut b) = tokio::io::duplex(1024);
            let a_result = do_handshake(a);
            let buf = vec![MAGIC_BYTE; i];
            b.write_all(&buf).await.unwrap();
            let err = a_result.await.unwrap_err();
            assert_eq!(err.to_string(), "deadline has elapsed");
        }
    }
}
