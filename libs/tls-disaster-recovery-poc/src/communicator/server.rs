use std::sync::Arc;

use anyhow::Context;
use borsh::BorshDeserialize;
use mpc_tls::constants;
use tokio::{io::AsyncRead, net::TcpStream, sync::Mutex};
use tokio_util::sync::CancellationToken;

use crate::{
    constants::{HANDSHAKE_TIMEOUT, READ_BODY_TIMEOUT, READ_HDR_TIMEOUT},
    messages::{MAX_MESSAGE_LEN, Messages, PeerMessage},
    types::{CommPeers, CommunicatorPeerId},
};

pub async fn recv_loop<R: AsyncRead + Unpin>(
    mut stream: R,
    cancel: CancellationToken,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    peer_id: CommunicatorPeerId,
) -> anyhow::Result<()> {
    let mut received_bytes: u64 = 0;

    loop {
        let len = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", %peer_id, "cancelled");
                return Ok(());
            },
            res = tokio::time::timeout(READ_HDR_TIMEOUT, stream.read_u32()) => {
                match res {
                    Err(_) => anyhow::bail!("header read timed out"),
                    Ok(Err(e)) => return Err(e).context("failed to read header"),
                    Ok(Ok(n)) => n,
                }
            }
        };

        if len == 0 {
            // Optional: treat zero-length as protocol error
            anyhow::bail!("unexpected zero-length message");
        }
        if len > MAX_MESSAGE_LEN {
            anyhow::bail!("message too long: {}", len);
        }

        let mut buf = vec![0u8; len as usize];

        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", %peer_id, "cancelled during body read");
                return Ok(());
            },
            res = tokio::time::timeout(READ_BODY_TIMEOUT, stream.read_exact(&mut buf)) => {
                match res {
                    Err(_) => anyhow::bail!("body read timed out"),
                    Ok(Err(e)) => return Err(e).context("failed to read body"),
                    Ok(Ok(_)) => {}
                }
            }
        }

        received_bytes += 4 + len as u64;
        tracing::info!(target: "receiver", %peer_id, received_bytes, "received bytes");

        let packet = Messages::try_from_slice(&buf).context("failed to deserialize packet")?;
        match packet {
            Messages::KEEPALIVE => {}
            Messages::Secrets(_) => {
                message_sender.send(PeerMessage {
                    peer_id,
                    message: packet,
                })?;
            }
        }
    }
}
async fn accept_connection(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_stream: TcpStream,
    allowed_peer_keys: Arc<CommPeers>,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
) -> anyhow::Result<()> {
    let (stream, conn) = tokio::select! {
        _ = cancel.cancelled() => {
            anyhow::bail!("cancelled");
    }
        res = async {
            let mut stream = tls_acceptor.accept(tcp_stream).await?;
            let common_state = stream.get_ref().1;
            let peer_pk = mpc_tls::tls::extract_public_key(common_state)?;
            let Some(peer_id) = allowed_peer_keys.is_allowed(&peer_pk) else {
                anyhow::bail!("peer is not in list of allowed peers.");
            };
            tracing::info!("Performing P2P handshake with: {:?}", peer_id);
            handshake(&mut stream, HANDSHAKE_TIMEOUT)
                .await
                .context("p2p handshake")?;
            tracing::info!("(incoming) Concluded P2P handshake with: {:?}", peer_id);
            let cancel_recv = CancellationToken::new();
            Ok::<_, anyhow::Error>((stream, Connection{peer_id, cancel: cancel_recv}))
            } => res?,
    };
    connections.lock().await.insert(conn.clone());
    tokio::spawn(recv_loop(stream, conn.cancel, message_sender, conn.peer_id));
    Ok(())
}

async fn listen_incoming(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_listener: tokio::net::TcpListener,
    allowed_peer_keys: Arc<CommPeers>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
) {
    loop {
        let tcp_stream: TcpStream = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("listener cancelled; stopping accept loop");
                break;
            }
            res = tcp_listener.accept() => {
                match res {
                    Ok((s, addr)) => {
                        tracing::debug!(%addr, "accepted TCP connection");
                        s
                    }
                    Err(e) => {
                        tracing::warn!(error=%e, "accept failed; continuing");
                        continue;
                    }
                }
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let allowed = allowed_peer_keys.clone();
        let conns = connections.clone();
        let tx = message_sender.clone();
        let child = cancel.child_token();

        tokio::spawn(async move {
            if let Err(e) =
                accept_connection(tls_acceptor, tcp_stream, allowed, tx, child, conns).await
            {
                tracing::warn!(error=%e, "accept_connection failed");
            }
        });
    }
}

struct Server {
    server_config: Arc<rustls::server::ServerConfig>,
    my_port: u16,
    allowed_peer_keys: Arc<CommPeers>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
}

impl Server {
    pub fn new(
        server_config: Arc<rustls::server::ServerConfig>,
        my_port: u16,
        allowed_peer_keys: Arc<CommPeers>,
        cancel: CancellationToken,
        connections: Arc<Mutex<IncomingConnections>>,
    ) -> Self {
        Server {
            server_config,
            my_port,
            allowed_peer_keys,
            cancel,
            connections,
        }
    }
    pub async fn listen(
        &mut self,
        message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    ) -> anyhow::Result<()> {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());
        let tcp_listener = tokio::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            self.my_port,
        )))
        .await
        .context("TCP bind")?;
        tokio::spawn(listen_incoming(
            tls_acceptor,
            tcp_listener,
            self.allowed_peer_keys.clone(),
            self.cancel.child_token(),
            self.connections.clone(),
            message_sender,
        ));
        Ok(())
    }
}
