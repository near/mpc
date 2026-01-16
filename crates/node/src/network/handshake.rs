use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol_version::{KnownMpcProtocols, CURRENT_PROTOCOL_VERSION};

/// Arbitrary magic byte to distinguish from older protocol where we didn't send
/// the protocol version at all.
const MAGIC_BYTE: u8 = 0xcc;

#[derive(Debug, Clone, Copy)]
pub struct SenderHandshakeData {
    pub sender_connection_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ReceiverHandshakeData {
    pub min_expected_connection_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakeRole {
    Sender(SenderHandshakeData),
    Receiver(ReceiverHandshakeData),
}

impl HandshakeRole {
    /// Performs a P2P handshake over an async byte stream.
    /// **P2P handshake wire format (big endian)**
    ///
    /// Common prefix (both peers, always):
    /// ┌───────────────┬───────────────┐
    /// │ u8            │ u32           │
    /// │ MAGIC_BYTE    │ PROTOCOL_VER  │
    /// └───────────────┴───────────────┘
    ///
    /// Version-specific suffix:
    ///
    /// Pre2026:
    /// ┌───────────────┐
    /// │ (no payload)  │
    /// └───────────────┘
    ///
    /// Jan2026:
    ///
    /// Sender → Receiver:
    /// ┌──────────────────────────┐
    /// │ u32                      │
    /// │ sender_connection_id     │
    /// └──────────────────────────┘
    ///
    /// Receiver → Sender:
    /// ┌────────────────────────────┐
    /// │ u32                        │
    /// │ min_expected_connection_id │
    /// └────────────────────────────┘
    ///
    /// **Differences between receiver and sender:**
    /// - Receiver **reads** common prefix before writing it, so the sender **must** write the prefix before
    ///   reading.
    ///   This is ensures that the receiver can stop the sender from concluding the handshake and
    ///   thus early-aborting the connection attempt. This may no longer be required onec all nodes
    ///   migrate to Jan2026 protocol.
    ///
    /// **Variable explanation:**
    /// - `MAGIC_BYTE`: to distinguish this protocol from (much) earlier protocol versions that did
    ///   not include the byte.
    /// - `protocol_version`: the identifier for the current protocol version.  The responsibility
    ///   is on the newer protocol versions to communicate in a backwards compatible way.
    /// - `sender_connection_id`: an identifier for this connection by the sender
    /// - `min_expected_connection_id`: the minimum expected identifier for this connection..way
    pub async fn p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        self,
        conn: &mut T,
        timeout: std::time::Duration,
    ) -> anyhow::Result<HandshakeOutcome> {
        tokio::time::timeout(timeout, async move {
            match self {
                HandshakeRole::Sender(SenderHandshakeData {
                    sender_connection_id,
                }) => {
                    conn.write_u8(MAGIC_BYTE).await?;
                    conn.write_u32(CURRENT_PROTOCOL_VERSION.into()).await?;
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
                            anyhow::bail!(
                                "peer is using a legacy protocol: their version: {}, ours: {:?}",
                                peer_protocol_version,
                                CURRENT_PROTOCOL_VERSION,
                            )
                        }
                        KnownMpcProtocols::Pre2026 => HandshakeOutcome {
                            protocol_version: KnownMpcProtocols::Pre2026,
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
                HandshakeRole::Receiver(ReceiverHandshakeData {
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
                        KnownMpcProtocols::Pre2026 => {
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
                                protocol_version: KnownMpcProtocols::Pre2026,
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
            KnownMpcProtocols::Pre2026 => true,
            KnownMpcProtocols::Jan2026 => {
                self.min_expected_connection_id == 0
                    || self.min_expected_connection_id <= self.sender_connection_id
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HandshakeRole, ReceiverHandshakeData, SenderHandshakeData};
    use crate::network::handshake::{HandshakeOutcome, MAGIC_BYTE};
    use crate::protocol_version::{KnownMpcProtocols, CURRENT_PROTOCOL_VERSION};
    use std::future::Future;
    use std::ops::Range;
    use test_case::test_case;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[test_case(42, 42, true; "expecting connection id succeeds")]
    #[test_case(100, 0, false; "resetting connection id by sender fails")]
    #[test_case(22, 1, false; "lower than expected connection id fails")]
    #[test_case(0, 100, true; "higher than expected connection id succeeds")]
    fn test_p2p_handshake_outcome_jan_2026(
        min_expected_connection_id: u32,
        sender_connection_id: u32,
        outcome: bool,
    ) {
        let expected_res = HandshakeOutcome {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert_eq!(expected_res.accept_connection(), outcome);
    }

    #[test_case(42, 42, true; "same expected connection attempt succeeds")]
    #[test_case(100, 0, true; "resetting connection attempt always succeeds")]
    #[test_case(22, 1, true; "higher expected connection attempt succeeds")]
    #[test_case(0, 100, true; "lower expected connection attempt succeeds")]
    fn test_p2p_handshake_outcome_pre_2026_always_accepts(
        min_expected_connection_id: u32,
        sender_connection_id: u32,
        outcome: bool,
    ) {
        let expected_res = HandshakeOutcome {
            protocol_version: KnownMpcProtocols::Pre2026,
            sender_connection_id,
            min_expected_connection_id,
        };
        assert_eq!(expected_res.accept_connection(), outcome);
    }

    fn deprecated_protocols() -> Range<u32> {
        0..(CURRENT_PROTOCOL_VERSION as u32 - 1)
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    fn execute_handshake(
        mut stream: tokio::io::DuplexStream,
        role: HandshakeRole,
    ) -> impl Future<Output = anyhow::Result<HandshakeOutcome>> {
        let handle = tokio::spawn(async move { role.p2p_handshake(&mut stream, TIMEOUT).await });
        async move { handle.await? }
    }

    fn sender_role(sender_connection_id: u32) -> HandshakeRole {
        HandshakeRole::Sender(SenderHandshakeData {
            sender_connection_id,
        })
    }

    fn receive_role(min_expected_connection_id: u32) -> HandshakeRole {
        HandshakeRole::Receiver(ReceiverHandshakeData {
            min_expected_connection_id,
        })
    }

    #[test_case(receive_role(42); "receiver handshake fails on magic byte mismatch")]
    #[test_case(sender_role(42); "sender handshake fails on magic byte mismatche")]
    #[tokio::test]
    async fn test_p2p_handshake_invalid_magic_byte_sender(role: HandshakeRole) {
        let (alice, mut bob) = tokio::io::duplex(1024);
        let alice_handle = execute_handshake(alice, role);
        let buf = [0u8; 10];
        bob.write_all(&buf).await.unwrap();
        let err = alice_handle.await.unwrap_err();
        assert_eq!(err.to_string(), "Invalid magic byte in handshake");
    }

    #[test_case(receive_role(42); "receiver handshake must timeout if peer does not respond")]
    #[test_case(sender_role(42); "sender handshake must timeout if peer does not respond")]
    #[tokio::test]
    async fn test_p2p_handshake_response_too_short_and_hangs(role: HandshakeRole) {
        for i in 0..=4 {
            let (this_node, mut peer) = tokio::io::duplex(1024);
            let this_node_handle = execute_handshake(this_node, role);
            let buf = vec![MAGIC_BYTE; i];
            peer.write_all(&buf).await.unwrap();
            let err = this_node_handle.await.unwrap_err();
            assert_eq!(err.to_string(), "deadline has elapsed");
        }
    }

    #[test_case(42, 42; "same expected connection id")]
    #[test_case(100, 0; "resetting connection id")]
    #[test_case(22, 1; "lower than expected connection id")]
    #[test_case(0, 100; "higher than expected connection attempt")]
    #[tokio::test]
    async fn test_p2p_handshake_connection_attempt(
        min_expected_connection_id: u32,
        sender_connection_id: u32,
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

    #[test_case(receive_role(42); "receiver handshake must fail")]
    #[test_case(sender_role(42); "sender handshake must fail")]
    #[tokio::test]
    async fn test_p2p_handshake_fail_on_deprecated_protocols(role: HandshakeRole) {
        for deprecated_version in deprecated_protocols() {
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
    #[test_case(receive_role(CONNECTION_ATTEMPT); "receiver handshake must fail")]
    #[test_case(sender_role(CONNECTION_ATTEMPT); "sender handshake must fail")]
    #[tokio::test]
    async fn test_p2p_handshake_future_protocol(role: HandshakeRole) {
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

    #[test_case(receive_role(CONNECTION_ATTEMPT); "receiver handshake must not accept if connection exists")]
    #[tokio::test]
    async fn test_p2p_handshake_backwards_compatibility_decline_if_connection_exists(
        role: HandshakeRole,
    ) {
        let (this_node, old_node) = tokio::io::duplex(1024);
        let this_node_handle = execute_handshake(this_node, role);
        let old_node_handle = execute_legacy_handshake(old_node);
        let this_node_res = this_node_handle.await;
        let old_node_res = old_node_handle.await;
        assert!(old_node_res.is_err());
        assert!(this_node_res.is_err());
    }

    #[test_case(sender_role(CONNECTION_ATTEMPT); "sender handshake must be backwards compatible")]
    #[test_case(receive_role(0); "receiver handshake must be backwards compatible")]
    #[tokio::test]
    async fn test_p2p_handshake_backwards_compatibility(role: HandshakeRole) {
        let (this_node, old_node) = tokio::io::duplex(1024);
        let this_node_handle = execute_handshake(this_node, role);
        let old_node_handle = execute_legacy_handshake(old_node);
        let this_node_res = this_node_handle.await.unwrap();
        let old_node_res = old_node_handle.await;
        assert!(old_node_res.is_ok());
        assert_eq!(
            this_node_res,
            HandshakeOutcome {
                protocol_version: PREVIOUS_PROTOCOL_VERSION.try_into().unwrap(),
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

    const PREVIOUS_PROTOCOL_VERSION: u32 = 7;
    pub async fn legacy_p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut T,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async move {
            let mut handshake_buf = [0u8; 5];
            handshake_buf[0] = MAGIC_BYTE;
            handshake_buf[1..].copy_from_slice(&PREVIOUS_PROTOCOL_VERSION.to_be_bytes());
            conn.write_all(&handshake_buf).await?;

            let mut other_handshake = [0u8; 5];
            conn.read_exact(&mut other_handshake).await?;
            if other_handshake[0] != MAGIC_BYTE {
                anyhow::bail!("Invalid magic byte in handshake");
            }

            let other_protocol_version =
                u32::from_be_bytes(other_handshake[1..].try_into().unwrap());
            if other_protocol_version < PREVIOUS_PROTOCOL_VERSION {
                anyhow::bail!(
                    "Incompatible protocol version; we have {}, they have {}",
                    PREVIOUS_PROTOCOL_VERSION,
                    other_protocol_version
                );
            }
            anyhow::Ok(())
        })
        .await?
    }
}
