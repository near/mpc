use std::sync::Arc;

use rustls::{ClientConfig, CommonState, ServerConfig};
use rustls::{pki_types::PrivatePkcs8KeyDer, server::WebPkiClientVerifier};

///// Performs a p2p handshake with the other side of the connection; this is done the first thing
///// for each connection. Fails if the handshake result is unexpected.
//pub async fn p2p_handshake<T: AsyncRead + AsyncWrite + Unpin>(
//    conn: &mut T,
//    timeout: std::time::Duration,
//) -> anyhow::Result<()> {
//    tokio::time::timeout(timeout, async move {
//        let mut handshake_buf = [0u8; 5];
//        handshake_buf[0] = MAGIC_BYTE;
//        handshake_buf[1..].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
//        conn.write_all(&handshake_buf).await?;
//
//        let mut other_handshake = [0u8; 5];
//        conn.read_exact(&mut other_handshake).await?;
//        if other_handshake[0] != MAGIC_BYTE {
//            anyhow::bail!("Invalid magic byte in handshake");
//        }
//
//        let other_protocol_version = u32::from_be_bytes(other_handshake[1..].try_into().unwrap());
//        if other_protocol_version != PROTOCOL_VERSION {
//            anyhow::bail!(
//                "Incompatible protocol version; we have {}, they have {}",
//                PROTOCOL_VERSION,
//                other_protocol_version
//            );
//        }
//        anyhow::Ok(())
//    })
//    .await?
//}

fn main() {
    println!("Hello, world!");
}
