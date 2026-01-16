use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol_version::{KnownMpcProtocols, CURRENT_PROTOCOL_VERSION};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTE: u8 = 0xcc;

#[derive(Debug, Clone, Copy)]
pub struct DialerData {
    pub sender_connection_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ListenerData {
    pub min_expected_connection_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakeRole {
    Dialer(DialerData),
    Listener(ListenerData),
}

impl HandshakeRole {
    /// Performs a P2P handshake over an async byte stream.
    /// **P2P handshake wire format (big endian)**
    ///
    /// Common prefix (both peers, all supported protocol versions):
    /// ┌───────────────┬───────────────────┐
    /// │ u8            │ u32               │
    /// │ MAGIC_BYTE    │ PROTOCOL_VERSION  │
    /// └───────────────┴───────────────────┘
    ///
    /// Version-specific data:
    ///
    /// Dec2025:
    /// ┌───────────────┐
    /// │ (no payload)  │
    /// └───────────────┘
    ///
    /// Jan2026:
    ///
    /// Sender → Listener:
    /// ┌──────────────────────────┐
    /// │ u32                      │
    /// │ sender_connection_id     │
    /// └──────────────────────────┘
    ///
    /// Listener → Dialer:
    /// ┌────────────────────────────┐
    /// │ u32                        │
    /// │ min_expected_connection_id │
    /// └────────────────────────────┘
    ///
    /// **Differences between receiver and sender:**
    /// - Listener **reads** common prefix before writing it, so the sender **must** write the prefix before
    ///   reading.
    ///   This is ensures that the receiver can stop the sender from concluding the handshake and
    ///   thus early-aborting the connection attempt. This may no longer be required once all nodes
    ///   migrate to Jan2026 protocol.
    ///
    /// **Variable explanation:**
    /// - `MAGIC_BYTE`: to distinguish this protocol from (much) earlier protocol versions that did
    ///   not include the byte.
    /// - `PROTOCOL_VERSION`: the identifier for the current protocol version.  The responsibility
    ///   is on the newer protocol versions to communicate in a backwards compatible way.
    /// - `sender_connection_id`: an identifier for this connection by the sender
    /// - `min_expected_connection_id`: the minimum expected identifier for this connection.
    pub async fn p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        conn: &mut T,
        timeout: std::time::Duration,
    ) -> anyhow::Result<HandshakeOutcome> {
        tokio::time::timeout(timeout, async move {
            match self {
                HandshakeRole::Dialer(DialerData {
                    sender_connection_id,
                }) => {
                    let mut buf = [0u8; 5];
                    buf[0] = MAGIC_BYTE;
                    let version: u32 = CURRENT_PROTOCOL_VERSION.into();
                    buf[1..5].copy_from_slice(&version.to_be_bytes());
                    conn.write_all(&buf).await?;
                    let other_magic_byte: u8 = conn.read_u8().await?;
                    if other_magic_byte != MAGIC_BYTE {
                        anyhow::bail!("Invalid magic byte in handshake")
                    }
                    let peer_protocol_version = conn.read_u32().await?;
                    let protocol_version: KnownMpcProtocols = peer_protocol_version
                        .try_into()
                        .unwrap_or(CURRENT_PROTOCOL_VERSION);
                    let outcome = match protocol_version {
                        KnownMpcProtocols::Unsupported => {
                            anyhow::bail!(
                                "peer is using a legacy protocol: their version: {}, ours: {:?}",
                                peer_protocol_version,
                                CURRENT_PROTOCOL_VERSION,
                            )
                        }
                        KnownMpcProtocols::Dec2025 => HandshakeOutcome {
                            protocol_version: KnownMpcProtocols::Dec2025,
                            sender_connection_id: 0,
                            min_expected_connection_id: 0, // by default, we assume this
                                                           // connection is accepted
                        },
                        KnownMpcProtocols::Jan2026 => {
                            conn.write_u32(sender_connection_id).await?;
                            let min_expected_connection_id = conn.read_u32().await?;
                            HandshakeOutcome {
                                protocol_version,
                                sender_connection_id,
                                min_expected_connection_id,
                            }
                        }
                    };
                    Ok(outcome)
                }
                HandshakeRole::Listener(ListenerData {
                    min_expected_connection_id,
                }) => {
                    let other_magic_byte: u8 = conn.read_u8().await?;
                    if other_magic_byte != MAGIC_BYTE {
                        anyhow::bail!("Invalid magic byte in handshake");
                    }
                    let peer_protocol_version = conn.read_u32().await?;
                    let protocol_version: KnownMpcProtocols = peer_protocol_version
                        .try_into()
                        .unwrap_or(CURRENT_PROTOCOL_VERSION);
                    let outcome = match protocol_version {
                        KnownMpcProtocols::Unsupported => {
                            // we don't even respond, we just bail
                            anyhow::bail!(
                                "peer is using a legacy protocol: their version: {}, ours: {:?}",
                                peer_protocol_version,
                                CURRENT_PROTOCOL_VERSION,
                            )
                        }
                        KnownMpcProtocols::Dec2025 => {
                            if min_expected_connection_id != 0 {
                                // we have an existing connection with this peer, so we are not
                                // interested in responding - we don't conclude the handshake and
                                // return an error.
                                anyhow::bail!("peer is already connected to us");
                            }
                            // we have no existing connection with this peer and are happy to
                            // accept this one.
                            conn.write_u8(MAGIC_BYTE).await?;
                            conn.write_u32(CURRENT_PROTOCOL_VERSION.into()).await?;
                            HandshakeOutcome {
                                protocol_version: KnownMpcProtocols::Dec2025,
                                sender_connection_id: 0,
                                min_expected_connection_id,
                            }
                        }
                        KnownMpcProtocols::Jan2026 => {
                            conn.write_u8(MAGIC_BYTE).await?;
                            conn.write_u32(CURRENT_PROTOCOL_VERSION.into()).await?;
                            conn.write_u32(min_expected_connection_id).await?;
                            let sender_connection_id = conn.read_u32().await?;
                            HandshakeOutcome {
                                protocol_version,
                                sender_connection_id,
                                min_expected_connection_id,
                            }
                        }
                    };
                    Ok(outcome)
                }
            }
        })
        .await?
    }
}

#[derive(Debug, PartialEq)]
pub struct HandshakeOutcome {
    pub protocol_version: KnownMpcProtocols,
    pub sender_connection_id: u32,
    pub min_expected_connection_id: u32,
}

impl HandshakeOutcome {
    /// returns a bool indicating if the connection can be accepted or not
    /// we accept the connection if `min_expected_connection_id` is zero (indicating the receiver
    /// node does not yet have a connection with the node), or if
    /// `min_expected_connection_id<=sender_connection_id`
    pub fn accept_connection(&self) -> bool {
        match self.protocol_version {
            KnownMpcProtocols::Unsupported => false,
            KnownMpcProtocols::Dec2025 => true,
            KnownMpcProtocols::Jan2026 => {
                self.min_expected_connection_id <= self.sender_connection_id
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DialerData, HandshakeRole, ListenerData};
    use crate::network::handshake::{HandshakeOutcome, MAGIC_BYTE};
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
    fn test_p2p_handshake_outcome_jan_2026(
        #[case] min_expected_connection_id: u32,
        #[case] sender_connection_id: u32,
        #[case] outcome: bool,
    ) {
        let expected_res = HandshakeOutcome {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert_eq!(expected_res.accept_connection(), outcome);
    }

    #[rstest]
    #[case::same_expected_connection_attempt(42, 42)]
    #[case::resetting_connection_attempt(100, 0)]
    #[case::higher_expected_connection_attempt(22, 1)]
    #[case::lower_expected_connection_attempt(0, 100)]
    fn test_p2p_handshake_outcome_pre_2026_always_accepts(
        #[case] min_expected_connection_id: u32,
        #[case] sender_connection_id: u32,
    ) {
        let expected_res = HandshakeOutcome {
            protocol_version: KnownMpcProtocols::Dec2025,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert!(expected_res.accept_connection());
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
    const DEC_2025_PROTOCOL_VERSION: u32 = KnownMpcProtocols::Dec2025 as u32;
    static DEPRECATED_PROTOCOLS: Range<u32> = 0..DEC_2025_PROTOCOL_VERSION;

    fn execute_handshake(
        mut stream: tokio::io::DuplexStream,
        role: HandshakeRole,
    ) -> impl Future<Output = anyhow::Result<HandshakeOutcome>> {
        let handle = tokio::spawn(async move { role.p2p_handshake(&mut stream, TIMEOUT).await });
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
        let expected_res = HandshakeOutcome {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert_eq!(receiver_result, expected_res);
        assert_eq!(sender_result, expected_res);
    }

    #[rstest]
    #[tokio::test]
    #[case::receiver_handshake_must_fail(receive_role(42))]
    #[case::sender_handshake_must_fail(sender_role(42))]
    async fn test_p2p_handshake_fail_on_deprecated_protocols(#[case] role: HandshakeRole) {
        for deprecated_version in DEPRECATED_PROTOCOLS.clone() {
            let (alice, mut bob) = tokio::io::duplex(1024);
            let alice_handle = execute_handshake(alice, role);

            let mut buf = [0u8; 5];
            buf[0] = MAGIC_BYTE;
            buf[1..].copy_from_slice(&(deprecated_version).to_be_bytes());
            bob.write_all(&buf).await.unwrap();
            let err = alice_handle.await.unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "peer is using a legacy protocol: their version: {}, ours: {:?}",
                    deprecated_version, CURRENT_PROTOCOL_VERSION
                )
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
        let future_version: u32 = CURRENT_PROTOCOL_VERSION as u32 + 1;

        let mut buf = [0u8; 10];
        buf[0] = MAGIC_BYTE;
        buf[1..5].copy_from_slice(&(future_version).to_be_bytes());
        buf[5..9].copy_from_slice(&(CONNECTION_ATTEMPT).to_be_bytes());
        bob.write_all(&buf).await.unwrap();
        let res = alice_handle.await.unwrap();
        assert_eq!(
            res,
            HandshakeOutcome {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                sender_connection_id: CONNECTION_ATTEMPT,
                min_expected_connection_id: CONNECTION_ATTEMPT,
            }
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
        let this_node_res = this_node_handle.await;
        let old_node_res = old_node_handle.await;
        assert!(old_node_res.is_err());
        assert!(this_node_res.is_err());
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
        assert_eq!(
            this_node_res,
            HandshakeOutcome {
                protocol_version: DEC_2025_PROTOCOL_VERSION.try_into().unwrap(),
                min_expected_connection_id: 0,
                sender_connection_id: 0,
            }
        );
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
            let mut handshake_buf = [0u8; 5];
            handshake_buf[0] = MAGIC_BYTE;
            handshake_buf[1..].copy_from_slice(&DEC_2025_PROTOCOL_VERSION.to_be_bytes());
            conn.write_all(&handshake_buf).await?;

            let mut other_handshake = [0u8; 5];
            conn.read_exact(&mut other_handshake).await?;
            if other_handshake[0] != MAGIC_BYTE {
                anyhow::bail!("Invalid magic byte in handshake");
            }

            let other_protocol_version =
                u32::from_be_bytes(other_handshake[1..].try_into().unwrap());
            if other_protocol_version < DEC_2025_PROTOCOL_VERSION {
                anyhow::bail!(
                    "Incompatible protocol version; we have {}, they have {}",
                    DEC_2025_PROTOCOL_VERSION,
                    other_protocol_version
                );
            }
            anyhow::Ok(())
        })
        .await?
    }
}
