//! A fake Sui `LedgerService` spoken over real gRPC, shared by the tests of both health-check
//! routes: the mock HTTP server the other chains use cannot answer a gRPC call.

use std::time::Duration;

use foreign_chain_rpc_interfaces::sui::Status;
use foreign_chain_rpc_interfaces::sui::proto::ledger_service_server::{
    LedgerService, LedgerServiceServer,
};
use foreign_chain_rpc_interfaces::sui::proto::{GetServiceInfoRequest, GetServiceInfoResponse};

/// Sui's genesis checkpoint digest, base58.
pub const SUI_MAINNET: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
pub const SUI_TESTNET: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";

/// Only `GetServiceInfo` is answered; the rest keep their generated `unimplemented` default.
struct FakeSuiLedger {
    chain_id: String,
    delay: Duration,
}

#[tonic::async_trait]
impl LedgerService for FakeSuiLedger {
    async fn get_service_info(
        &self,
        _request: tonic::Request<GetServiceInfoRequest>,
    ) -> Result<tonic::Response<GetServiceInfoResponse>, Status> {
        tokio::time::sleep(self.delay).await;
        Ok(tonic::Response::new(
            GetServiceInfoResponse::default().with_chain_id(&self.chain_id),
        ))
    }
}

/// Serves a [`FakeSuiLedger`] on a loopback port until dropped.
pub struct FakeSuiServer {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSuiServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_sui(ledger: FakeSuiLedger) -> FakeSuiServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LedgerServiceServer::new(ledger))
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener))
            .await
            .expect("the fake Sui ledger should keep serving until the test drops it");
    });
    FakeSuiServer { url, task }
}

pub async fn sui_on_chain(chain_id: &str) -> FakeSuiServer {
    serve_sui(FakeSuiLedger {
        chain_id: chain_id.to_string(),
        delay: Duration::ZERO,
    })
    .await
}

/// Answers far later than any deadline a test sets, so the caller's own deadline decides.
pub async fn sui_never_answering_in_time() -> FakeSuiServer {
    serve_sui(FakeSuiLedger {
        chain_id: SUI_MAINNET.to_string(),
        delay: Duration::from_secs(30),
    })
    .await
}
