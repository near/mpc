use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol_version::{KnownMpcProtocols, CURRENT_PROTOCOL_VERSION};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTE: u8 = 0xcc;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DialerData {
    pub sender_connection_id: u32,
}

pub(crate) const MIN_EXPECTED_CONNECTION_ID: u32 = 0;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ListenerData {
    pub min_expected_connection_id: u32,
}

/// Performs a P2P handshake over an async byte stream as the dialer
///
/// 1. Writes 5 bytes to byte stream
///    Dialer --> Listener:
///    ┌───────────────┬───────────────────────────┐
///    │ u8            │ u32                       │
///    │ MAGIC_BYTE    │ CURRENT_PROTOCOL_VERSION  │
///    └───────────────┴───────────────────────────┘
/// 2. Reads 5 bytes from byte stream
///    Dialer <-- Listener:
///    ┌───────────────┬────────────────────────────┐
///    │ u8            │ u32                        │
///    │ MAGIC_BYTE    │ LISTENER_PROTOCOL_VERSION  │
///    └───────────────┴────────────────────────────┘
///
/// 3. Compares `LISTENER_PROTOCOL_VERSION` against the list of KnownMpcProtocols and engages in
///    *Version-specific* behavior:
///     - *Unsupported:*
///       This function returns HandshakeOutcome::Unsupported(peer_protocol_version) in case the listener is running a deprecated
///       protocol version.
///     - *Dec2025:*
///       Returns HandshakeOutcome::Dec2025(true), indicating that the listener is running Dec2025
///       protocol and is expected to accept this connection.
///     - *Jan2026:*
///       1. Writes `sender_connection_id` to byte stream
///          Dialer --> Listener:
///          ┌──────────────────────────┐
///          │ u32                      │
///          │ sender_connection_id     │
///          └──────────────────────────┘
///       2. Reads `min_expected_connection_id` from byte stream:
///          Dialer <-- Listener:
///          ┌────────────────────────────┐
///          │ u32                        │
///          │ min_expected_connection_id │
///          └────────────────────────────┘
///       3. Returns HandshakeOutcome::Jan2026(ConnectionInfo)
pub(crate) async fn p2p_handshake_dialer<T: AsyncRead + AsyncWrite + Unpin>(
    dialer_data: DialerData,
    conn: &mut T,
) -> anyhow::Result<HandshakeOutcome> {
    let DialerData {
        sender_connection_id,
    } = dialer_data;
    write_magic_byte_and_protocol_version(conn).await?;
    let peer_protocol_version = read_magic_byte_and_protocol_version(conn).await?;
    let peer_protocol_version: KnownMpcProtocols = peer_protocol_version.into();
    let outcome = match peer_protocol_version {
        KnownMpcProtocols::Unsupported => {
            tracing::warn!(
                "peer is using a legacy protocol: their version: {}, ours: {:?}",
                peer_protocol_version,
                CURRENT_PROTOCOL_VERSION,
            );
            HandshakeOutcome::Unsupported(peer_protocol_version)
        }
        KnownMpcProtocols::Dec2025 => {
            // if we get here, the connection is always accepted
            HandshakeOutcome::Dec2025(true)
        }
        KnownMpcProtocols::Jan2026 | KnownMpcProtocols::Unknown(_) => {
            conn.write_u32(sender_connection_id).await?;
            let min_expected_connection_id = conn.read_u32().await?;
            HandshakeOutcome::Jan2026(ConnectionInfo {
                peer_protocol_version,
                sender_connection_id,
                min_expected_connection_id,
            })
        }
    };
    Ok(outcome)
}

/// Performs a P2P handshake over an async byte stream as the listener
///
/// 1. Reads 5 bytes to byte stream
///    Listener <-- Dialer:
///    ┌───────────────┬──────────────────────────┐
///    │ u8            │ u32                      │
///    │ MAGIC_BYTE    │ DIALER_PROTOCOL_VERSION  │
///    └───────────────┴──────────────────────────┘
///
/// 2. Compares `DIALER_PROTOCOL_VERSION` against the list of KnownMpcProtocols and engages in
///    *Version-specific* behavior:
///     - *Unsupported:*
///       The listener aborts the handshake, not writing anything to the byte stream.
///       This function returns HandshakeOutcome::Unsupported(peer_protocol_version).
///     - *Dec2025:*
///       If `min_expected_connection_id` is not 0, then this function aborts the handshake, not writing
///       anything to byte stream and returns HandshakeOutcome::Dec2025(false).
///       If `min_expected_connection_id` is 0, then this function writes `MAGIC_BYTE` and
///       `CURRENT_PROTOCOL_VERSION` to byte steram and returns HandshakeOutcome::Dec2025(true)
///       Listener --> Dialer:
///       ┌───────────────┬───────────────────────────┐
///       │ u8            │ u32                       │
///       │ MAGIC_BYTE    │ CURRENT_PROTOCOL_VERSION  │
///       └───────────────┴───────────────────────────┘
///     - *Jan2026:*
///         1. Sends MAGIC_BYTE, CURRENT_PROTOCOL_VERSION and min_expected_connection_id to Dialer.
///            Listener --> Dialer:
///            ┌───────────────┬───────────────────────────┬────────────────────────────┐
///            │ u8            │ u32                       │ u32                        │
///            │ MAGIC_BYTE    │ CURRENT_PROTOCOL_VERSION  │ min_expected_connection_id │
///            └───────────────┴───────────────────────────┴────────────────────────────┘
///
///         2. Reads `sender_connection_id` from byte stream:
///            Listener <-- Dialer:
///            ┌──────────────────────┐
///            │ u32                  │
///            │ sender_connection_id │
///            └──────────────────────┘
///         3. Returns HandshakeOutcome::Jan2026(ConnectionInfo)
pub(crate) async fn p2p_handshake_listener<T: AsyncRead + AsyncWrite + Unpin>(
    listener_data: ListenerData,
    conn: &mut T,
) -> anyhow::Result<HandshakeOutcome> {
    let ListenerData {
        min_expected_connection_id,
    } = listener_data;
    let peer_protocol_version = read_magic_byte_and_protocol_version(conn).await?;
    let peer_protocol_version: KnownMpcProtocols = peer_protocol_version.into();
    let outcome = match peer_protocol_version {
        KnownMpcProtocols::Unsupported => {
            tracing::warn!(
                "peer is using a legacy protocol: their version: {}, ours: {:?}",
                peer_protocol_version,
                CURRENT_PROTOCOL_VERSION,
            );
            HandshakeOutcome::Unsupported(peer_protocol_version)
        }
        KnownMpcProtocols::Dec2025 => {
            if min_expected_connection_id == MIN_EXPECTED_CONNECTION_ID {
                // we have no existing connection with this peer and are happy to
                // accept this one.
                write_magic_byte_and_protocol_version(conn).await?;
                HandshakeOutcome::Dec2025(true)
            } else {
                // we have an existing connection with this peer, so we are not
                // interested in responding - we don't conclude the handshake and
                // return an error.
                tracing::warn!("peer is already connected to us");
                HandshakeOutcome::Dec2025(false)
            }
        }
        KnownMpcProtocols::Jan2026 | KnownMpcProtocols::Unknown(_) => {
            write_magic_byte_protocol_version_and_expected_connection_version(
                conn,
                min_expected_connection_id,
            )
            .await?;
            let sender_connection_id = conn.read_u32().await?;
            HandshakeOutcome::Jan2026(ConnectionInfo {
                peer_protocol_version,
                sender_connection_id,
                min_expected_connection_id,
            })
        }
    };
    Ok(outcome)
}

/// wrtes 5 bytes to `conn` (big-endian)
///
/// Offset  Size  Type  Name
/// ──────────────────────────────
/// 0       1     u8    MAGIC_BYTE
/// 1       4     u32   CURRENT_PROTOCOL_VERSION
///
/// ┌───────────────┬───────────────────────────┐
/// │ u8            │ u32                       │
/// │ MAGIC_BYTE    │ CURRENT_PROTOCOL_VERSION  │
/// └───────────────┴───────────────────────────┘
async fn write_magic_byte_and_protocol_version<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(5);
    buf.put_u8(MAGIC_BYTE);
    buf.put_u32(CURRENT_PROTOCOL_VERSION.into());
    conn.write_all(&buf).await?;
    Ok(())
}

/// writes 9 bytes to `conn` (big-endian)
///
/// Offset  Size  Type  Name
/// ────────────────────────────────────────
/// 0       1     u8    MAGIC_BYTE
/// 1       4     u32   CURRENT_PROTOCOL_VERSION
/// 5       4     u32   min_expected_connection_id
///
/// ┌───────────────┬───────────────────────────┬────────────────────────────┐
/// │ u8            │ u32                       │ u32                        │
/// │ MAGIC_BYTE    │ CURRENT_PROTOCOL_VERSION  │ min_expected_connection_id │
/// └───────────────┴───────────────────────────┴────────────────────────────┘
async fn write_magic_byte_protocol_version_and_expected_connection_version<
    T: AsyncRead + AsyncWrite + Unpin,
>(
    conn: &mut T,
    min_expected_connection_id: u32,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(MAGIC_BYTE);
    buf.put_u32(CURRENT_PROTOCOL_VERSION.into());
    buf.put_u32(min_expected_connection_id);
    conn.write_all(&buf).await?;
    Ok(())
}

/// reads 5 bytes from `conn`
/// returns an error if first byte does not match `MAGIC_BYTE`
///
/// Offset  Size  Type  Name
/// ──────────────────────────────
/// 0       1     u8    MAGIC_BYTE
/// 1       4     u32   PROTOCOL_VERSION
async fn read_magic_byte_and_protocol_version<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> anyhow::Result<u32> {
    let other_magic_byte: u8 = conn.read_u8().await?;
    if other_magic_byte != MAGIC_BYTE {
        anyhow::bail!("Invalid magic byte in handshake")
    }
    let peer_protocol_version = conn.read_u32().await?;
    Ok(peer_protocol_version)
}

#[derive(Debug, PartialEq)]
pub(crate) enum HandshakeOutcome {
    Unsupported(KnownMpcProtocols),
    Dec2025(bool),
    Jan2026(ConnectionInfo),
}

#[derive(Debug, PartialEq)]
pub(crate) struct ConnectionInfo {
    pub peer_protocol_version: KnownMpcProtocols,
    pub sender_connection_id: u32,
    pub min_expected_connection_id: u32,
}

impl ConnectionInfo {
    /// returns a bool indicating if the connection can be accepted or not
    /// we accept the connectin if and only if
    /// `min_expected_connection_id <= sender_connection_id`
    pub(crate) fn is_accepted(&self) -> bool {
        self.min_expected_connection_id <= self.sender_connection_id
    }
}

#[cfg(test)]
mod tests {
    use super::{
        p2p_handshake_dialer, p2p_handshake_listener, DialerData, HandshakeOutcome, ListenerData,
    };
    use crate::network::handshake::{ConnectionInfo, MAGIC_BYTE};
    use crate::protocol_version::{KnownMpcProtocols, CURRENT_PROTOCOL_VERSION};
    use rstest::*;
    use std::future::Future;
    use std::ops::Range;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[rstest]
    #[case::expecting_connection_id_succeeds(42, 42, true)]
    #[case::resetting_connection_id_by_sender_fails(100, 0, false)]
    #[case::lower_than_expected_connection_id_fails(22, 1, false)]
    #[case::higher_than_expected_connection_id_succeeds(0, 100, true)]
    fn test_p2p_handshake_outcome_data_jan_2026(
        #[case] min_expected_connection_id: u32,
        #[case] sender_connection_id: u32,
        #[case] outcome: bool,
    ) {
        let expected_res = ConnectionInfo {
            peer_protocol_version: CURRENT_PROTOCOL_VERSION,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert_eq!(expected_res.is_accepted(), outcome);
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    #[derive(Debug, Clone, Copy)]
    pub enum HandshakeRole {
        Dialer(DialerData),
        Listener(ListenerData),
    }

    fn execute_handshake(
        mut stream: tokio::io::DuplexStream,
        role: HandshakeRole,
    ) -> impl Future<Output = anyhow::Result<HandshakeOutcome>> {
        let handle = tokio::spawn(async move {
            match role {
                HandshakeRole::Dialer(dialer_data) => {
                    tokio::time::timeout(TIMEOUT, p2p_handshake_dialer(dialer_data, &mut stream))
                        .await?
                }
                HandshakeRole::Listener(listener_data) => {
                    tokio::time::timeout(
                        TIMEOUT,
                        p2p_handshake_listener(listener_data, &mut stream),
                    )
                    .await?
                }
            }
        });
        async move { handle.await? }
    }

    fn sender_role(sender_connection_id: u32) -> HandshakeRole {
        HandshakeRole::Dialer(DialerData {
            sender_connection_id,
        })
    }

    fn receive_role(min_expected_connection_id: u32) -> HandshakeRole {
        HandshakeRole::Listener(ListenerData {
            min_expected_connection_id,
        })
    }

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_fails_on_magic_byte_mismatch(receive_role(42))]
    #[case::sender_handshake_fails_on_magic_byte_mismatch(sender_role(42))]
    async fn test_p2p_handshake_invalid_magic_byte_sender(#[case] role: HandshakeRole) {
        let (alice, mut bob) = tokio::io::duplex(1024);
        let alice_handle = execute_handshake(alice, role);
        let buf = [0u8; 10];
        bob.write_all(&buf).await.unwrap();
        let err = alice_handle.await.unwrap_err();
        assert_eq!(err.to_string(), "Invalid magic byte in handshake");
    }

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_times_out_when_peer_does_not_respond(receive_role(42))]
    #[case::sender_handshake_times_out_when_peer_does_not_respond(sender_role(42))]
    async fn test_p2p_handshake_response_too_short_and_hangs(#[case] role: HandshakeRole) {
        for i in 0..=4 {
            let (this_node, mut peer) = tokio::io::duplex(1024);
            let this_node_handle = execute_handshake(this_node, role);
            let buf = vec![MAGIC_BYTE; i];
            peer.write_all(&buf).await.unwrap();
            let err = this_node_handle.await.unwrap_err();
            assert_eq!(err.to_string(), "deadline has elapsed");
        }
    }

    #[rstest]
    #[tokio::test]
    #[case::same_expected_connection_id(42, 42)]
    #[case::resetting_connection_id(100, 0)]
    #[case::lower_than_expected_connection_id(22, 1)]
    #[case::higher_than_expected_connection_attempt(0, 100)]
    async fn test_p2p_handshake_connection_attempt(
        #[case] min_expected_connection_id: u32,
        #[case] sender_connection_id: u32,
    ) {
        let (sender, receiver) = tokio::io::duplex(1024);
        let sender_handle = execute_handshake(sender, sender_role(sender_connection_id));
        let receiver_handle = execute_handshake(receiver, receive_role(min_expected_connection_id));
        let sender_result = sender_handle.await.unwrap();
        let receiver_result = receiver_handle.await.unwrap();
        let expected_res = HandshakeOutcome::Jan2026(ConnectionInfo {
            peer_protocol_version: CURRENT_PROTOCOL_VERSION,
            sender_connection_id,
            min_expected_connection_id,
        });
        assert_eq!(receiver_result, expected_res);
        assert_eq!(sender_result, expected_res);
    }

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_must_fail(receive_role(42))]
    #[case::sender_handshake_must_fail(sender_role(42))]
    async fn test_p2p_handshake_fail_on_deprecated_protocols(#[case] role: HandshakeRole) {
        let deprecated_protocols: Range<u32> = 0..KnownMpcProtocols::Dec2025.into();
        for deprecated_version in deprecated_protocols.clone() {
            let (alice, mut bob) = tokio::io::duplex(1024);
            let alice_handle = execute_handshake(alice, role);

            let mut buf = [0u8; 5];
            buf[0] = MAGIC_BYTE;
            buf[1..].copy_from_slice(&(deprecated_version).to_be_bytes());
            bob.write_all(&buf).await.unwrap();
            let res = alice_handle.await.unwrap();
            assert_eq!(
                res,
                HandshakeOutcome::Unsupported(deprecated_version.into())
            );
        }
    }

    const CONNECTION_ATTEMPT: u32 = 42;

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_accepts_future_protocol(receive_role(CONNECTION_ATTEMPT))]
    #[case::sender_handshake_accepts_future_protocol(sender_role(CONNECTION_ATTEMPT))]
    async fn test_p2p_handshake_future_protocol(#[case] role: HandshakeRole) {
        let (alice, mut bob) = tokio::io::duplex(1024);
        let alice_handle = execute_handshake(alice, role);
        let current: u32 = CURRENT_PROTOCOL_VERSION.into();
        let future_version: u32 = current + 1;

        let mut buf = [0u8; 10];
        buf[0] = MAGIC_BYTE;
        buf[1..5].copy_from_slice(&(future_version).to_be_bytes());
        buf[5..9].copy_from_slice(&(CONNECTION_ATTEMPT).to_be_bytes());
        bob.write_all(&buf).await.unwrap();
        let res = alice_handle.await.unwrap();
        assert_eq!(
            res,
            HandshakeOutcome::Jan2026(ConnectionInfo {
                peer_protocol_version: future_version.into(),
                sender_connection_id: CONNECTION_ATTEMPT,
                min_expected_connection_id: CONNECTION_ATTEMPT,
            })
        );
    }

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_declines_if_connection_exists(receive_role(CONNECTION_ATTEMPT))]
    async fn test_p2p_handshake_backwards_compatibility_decline_if_connection_exists(
        #[case] role: HandshakeRole,
    ) {
        let (this_node, old_node) = tokio::io::duplex(1024);
        let this_node_handle = execute_handshake(this_node, role);
        let old_node_handle = execute_legacy_handshake(old_node);
        let this_node_res = this_node_handle.await.unwrap();
        let old_node_res = old_node_handle.await;
        assert!(old_node_res.is_err());
        assert_eq!(this_node_res, HandshakeOutcome::Dec2025(false));
    }

    #[rstest]
    #[tokio::test]
    #[case::sender_handshake_must_be_backwards_compatible(sender_role(CONNECTION_ATTEMPT))]
    #[case::receiver_handshake_must_be_backwards_compatible(receive_role(0))]
    async fn test_p2p_handshake_backwards_compatibility(#[case] role: HandshakeRole) {
        let (this_node, old_node) = tokio::io::duplex(1024);
        let this_node_handle = execute_handshake(this_node, role);
        let old_node_handle = execute_legacy_handshake(old_node);
        let this_node_res = this_node_handle.await.unwrap();
        let old_node_res = old_node_handle.await;
        assert!(old_node_res.is_ok());
        assert_eq!(this_node_res, HandshakeOutcome::Dec2025(true));
    }

    fn execute_legacy_handshake(
        mut stream: tokio::io::DuplexStream,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let handle = tokio::spawn(async move { legacy_p2p_handshake(&mut stream, TIMEOUT).await });
        async move { handle.await? }
    }

    pub async fn legacy_p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut T,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async move {
            let dec_2025_protocol_version: u32 = KnownMpcProtocols::Dec2025.into();
            let mut handshake_buf = [0u8; 5];
            handshake_buf[0] = MAGIC_BYTE;
            handshake_buf[1..].copy_from_slice(&dec_2025_protocol_version.to_be_bytes());
            conn.write_all(&handshake_buf).await?;

            let mut other_handshake = [0u8; 5];
            conn.read_exact(&mut other_handshake).await?;
            if other_handshake[0] != MAGIC_BYTE {
                anyhow::bail!("Invalid magic byte in handshake");
            }

            let other_protocol_version =
                u32::from_be_bytes(other_handshake[1..].try_into().unwrap());
            if other_protocol_version < dec_2025_protocol_version {
                anyhow::bail!(
                    "Incompatible protocol version; we have {}, they have {}",
                    dec_2025_protocol_version,
                    other_protocol_version
                );
            }
            anyhow::Ok(())
        })
        .await?
    }
}
