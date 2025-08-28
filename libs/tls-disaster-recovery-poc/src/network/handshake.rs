use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTES: &[u8] = b"NEAR_MPC_BACKUP_SERVICE";
const BACKUP_SERVICE_PROTOCOL_VERSION: u16 = 0;
const HANDSHAKE_LEN: usize = MAGIC_BYTES.len() + 2;

/// Performs a p2p handshake with the other side of the connection; this is done the first thing
/// for each connection. Fails if the handshake result is unexpected.
pub async fn handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, async move {
        // Send our protocol version
        let mut handshake_buf = [0u8; HANDSHAKE_LEN];
        handshake_buf[..MAGIC_BYTES.len()].copy_from_slice(MAGIC_BYTES);
        handshake_buf[MAGIC_BYTES.len()..]
            .copy_from_slice(&BACKUP_SERVICE_PROTOCOL_VERSION.to_be_bytes());
        conn.write_all(&handshake_buf).await?;

        // Receive their protocol version
        let mut incoming = [0u8; HANDSHAKE_LEN];
        conn.read_exact(&mut incoming).await?;

        // Verify magic prefix
        let (magic, ver_bytes) = incoming.split_at(MAGIC_BYTES.len());
        if magic != MAGIC_BYTES {
            anyhow::bail!("invalid magic bytes in handshake");
        }

        // Parse peer version (u16, BE)
        let ver = u16::from_be_bytes(ver_bytes.try_into().unwrap());
        if ver != BACKUP_SERVICE_PROTOCOL_VERSION {
            anyhow::bail!(
                "incompatible protocol version: local {BACKUP_SERVICE_PROTOCOL_VERSION}, peer {ver}"
            );
        }
        anyhow::Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use crate::handshake::BACKUP_SERVICE_PROTOCOL_VERSION;
    use crate::handshake::HANDSHAKE_LEN;
    use crate::handshake::MAGIC_BYTES;
    use crate::handshake::handshake;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

    fn do_handshake(mut a: tokio::io::DuplexStream) -> impl Future<Output = anyhow::Result<()>> {
        let handle = tokio::spawn(async move { handshake(&mut a, TEST_TIMEOUT).await });
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
    async fn test_p2p_handshake_different_version() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let mut buf = [0u8; HANDSHAKE_LEN];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[..MAGIC_BYTES.len()], *MAGIC_BYTES);
        assert_eq!(
            u16::from_be_bytes(buf[MAGIC_BYTES.len()..].try_into().unwrap()),
            BACKUP_SERVICE_PROTOCOL_VERSION
        );

        buf[MAGIC_BYTES.len()..]
            .copy_from_slice(&(BACKUP_SERVICE_PROTOCOL_VERSION + 1).to_be_bytes());
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "incompatible protocol version: local {}, peer {}",
                BACKUP_SERVICE_PROTOCOL_VERSION,
                BACKUP_SERVICE_PROTOCOL_VERSION + 1
            )
        );
    }

    #[tokio::test]
    async fn test_p2p_handshake_invalid_magic_byte() {
        let (a, mut b) = tokio::io::duplex(1024);
        let a_result = do_handshake(a);
        let mut buf = [0u8; HANDSHAKE_LEN];
        buf[MAGIC_BYTES.len()..].copy_from_slice(&BACKUP_SERVICE_PROTOCOL_VERSION.to_be_bytes());
        b.write_all(&buf).await.unwrap();
        let err = a_result.await.unwrap_err();
        assert_eq!(err.to_string(), "invalid magic bytes in handshake");
    }

    #[tokio::test]
    async fn test_p2p_handshake_response_too_short_and_hangs() {
        for i in 0..=MAGIC_BYTES.len() - 1 {
            let (a, mut b) = tokio::io::duplex(1024);
            let a_result = do_handshake(a);
            b.write_all(&MAGIC_BYTES[..i]).await.unwrap();
            let err = a_result.await.unwrap_err();
            assert_eq!(err.to_string(), "deadline has elapsed");
        }
    }
}
