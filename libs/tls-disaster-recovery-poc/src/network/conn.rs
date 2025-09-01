use crate::network::constants;
use crate::network::constants::MAX_MESSAGE_LEN;
use crate::network::messages::Messages;
use crate::network::types::Peer;
use anyhow::Context;
use borsh::BorshDeserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

/* --------------------------- */
/* Low level send and receive  */
/* --------------------------- */
pub(crate) async fn send<W>(
    mut writer: W,
    cancel: CancellationToken,
    mut receiver: tokio::sync::mpsc::Receiver<Messages>,
    peer: Peer,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut heartbeat_interval = tokio::time::interval(constants::HEARTBEAT_INTERVAL);
    heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut sent_bytes: u64 = 0;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!(target:"sender", "Peer: {:?} cancelled", peer.address);
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                return Ok(());
            }
            data = receiver.recv() => {
                let Some(data) = data else {
                    tracing::info!(target:"sender", "{:?} receiver dropped", peer.address);
                    cancel.cancel();
                    continue; // let biased arm run next iteration
                };

                let serialized = borsh::to_vec(&data)?;
                let len: u32 = serialized.len()
                    .try_into()
                    .context(format!("{:?} Message too long", peer.address))?;

                writer.write_u32(len).await?;
                writer.write_all(&serialized).await?;
                sent_bytes += 4 + len as u64;
                tracing::info!(target:"sender", "Sent {} bytes to {:?}", sent_bytes, peer.address);
            }

            // Heartbeat
            _ = heartbeat_interval.tick() => {
                if cancel.is_cancelled() {
                    continue; // let biased arm run next iteration
                }
                let packet = Messages::KEEPALIVE;
                let serialized = borsh::to_vec(&packet)?;
                let len: u32 = serialized.len()
                    .try_into()
                    .context(format!("{:?} Message too long", peer.address))?;

                writer.write_u32(len).await?;
                writer.write_all(&serialized).await?;
                sent_bytes = sent_bytes.saturating_add(4 + len as u64);
                tracing::trace!(target:"sender", sent_bytes, "sent heartbeat to {:?}", peer.address);
            }
        }
    }
}

pub(crate) async fn recv_loop<R>(
    mut reader: R,
    cancel: CancellationToken,
    inbound_message_sender: tokio::sync::mpsc::Sender<Messages>,
    peer: Peer,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut received_bytes: u64 = 0;

    loop {
        let len = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", "Peer: {:?} cancelled", peer.address);
                return Ok(());
            },
            res = tokio::time::timeout(constants::READ_HDR_TIMEOUT, reader.read_u32()) => {
                match res {
                    Err(_) => {
                        cancel.cancel();
                        anyhow::bail!("header read timed out for {:?}", peer.address)
                    }
                    Ok(Err(e)) => {
                        cancel.cancel();
                        return Err(e).context(format!("failed to read header for {:?}", peer.address));
                    }
                    Ok(Ok(n)) => n,
                }
            }
        };

        if len == 0 {
            cancel.cancel();
            anyhow::bail!("unexpected zero-length message");
        }
        if len > MAX_MESSAGE_LEN {
            cancel.cancel();
            anyhow::bail!("message too long: {}", len);
        }

        let mut buf = vec![0u8; len as usize];
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", "Peer {:?} cancelled during body read", peer.address);
                return Ok(());
            },
            res = tokio::time::timeout(constants::READ_BODY_TIMEOUT, reader.read_exact(&mut buf)) => {
                match res {
                    Err(_) =>{
                        cancel.cancel();
                        anyhow::bail!("body read timed out {:?}", peer.address)
                    },
                    Ok(Err(e)) => {
                        cancel.cancel();
                        return Err(e).context(format!("failed to read body {:?}", peer.address))
                    },
                    Ok(Ok(_)) => {}
                }
            }
        }

        received_bytes += 4 + len as u64;
        tracing::info!(target: "receiver", "Received {} from {:?}", received_bytes, peer.address);

        let packet = Messages::try_from_slice(&buf).context(format!(
            "failed to deserialize packet from {:?}",
            peer.address
        ))?;
        match packet {
            Messages::KEEPALIVE => {
                tracing::trace!(target:"receiver", "keepalive from {:?}", peer.address);
            }
            other => {
                if let Err(err) = inbound_message_sender.send(other).await {
                    cancel.cancel();
                    tracing::info!(target:"receiver", "downstream dropped for {:?}: {}", peer.address, err);
                    anyhow::bail!("channel closed");
                }
            }
        }
    }
}
