use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::PrivatePkcs8KeyDer;
use tempfile::NamedTempFile;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub struct HttpsProxy {
    address: SocketAddr,
    certificate_file: NamedTempFile,
    task: JoinHandle<()>,
}

impl HttpsProxy {
    pub async fn start(backend: SocketAddr) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![Ipv4Addr::LOCALHOST.to_string()])?;
        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let mut certificate_file = NamedTempFile::new()?;
        certificate_file.write_all(cert.pem().as_bytes())?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(forward(acceptor.clone(), client, backend));
            }
        });

        Ok(Self {
            address,
            certificate_file,
            task,
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.address)
    }

    /// PEM file holding the self-signed certificate.
    pub fn certificate_path(&self) -> &Path {
        self.certificate_file.path()
    }
}

impl Drop for HttpsProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward(acceptor: TlsAcceptor, client: TcpStream, backend: SocketAddr) {
    let result = async {
        let mut client = acceptor.accept(client).await?;
        let mut backend = TcpStream::connect(backend).await?;
        tokio::io::copy_bidirectional(&mut client, &mut backend).await
    }
    .await;
    // Also fires on healthy connections: clients commonly close without a TLS close_notify.
    if let Err(error) = result {
        tracing::debug!(%error, "https proxy connection ended with an error");
    }
}
