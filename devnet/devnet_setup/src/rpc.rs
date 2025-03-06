use crate::types::RpcConfig;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_jsonrpc_client::JsonRpcClient;
use std::ops::Deref;
use std::sync::Arc;

pub struct NearRpcClients {
    rpcs: Vec<NearRpcClient>,
}

struct NearRpcClient {
    client: Arc<JsonRpcClient>,
    receiver: flume::Receiver<()>,
    concurrency: Arc<tokio::sync::Semaphore>,
    rate_limit: usize,
}

impl NearRpcClient {
    fn new(config: RpcConfig) -> Self {
        let client = JsonRpcClient::connect(config.url);
        let concurrency = tokio::sync::Semaphore::new(config.max_concurrency);
        let (sender, receiver) = flume::bounded(config.rate_limit);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(1).div_f64(config.rate_limit as f64),
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if sender.send_async(()).await.is_err() {
                    break;
                }
            }
        });
        Self {
            client: Arc::new(client),
            receiver,
            concurrency: Arc::new(concurrency),
            rate_limit: config.rate_limit,
        }
    }

    async fn ready(&self) -> RpcClientPermit {
        let concurrency_permit = self.concurrency.clone().acquire_owned().await.unwrap();
        self.receiver.recv_async().await.unwrap();
        RpcClientPermit {
            _concurrency_permit: concurrency_permit,
            client: self.client.clone(),
        }
    }
}

pub struct RpcClientPermit {
    _concurrency_permit: tokio::sync::OwnedSemaphorePermit,
    client: Arc<JsonRpcClient>,
}

impl Deref for RpcClientPermit {
    type Target = JsonRpcClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl NearRpcClients {
    pub async fn new(rpcs: Vec<RpcConfig>) -> Self {
        let rpcs = rpcs
            .into_iter()
            .map(|config| NearRpcClient::new(config))
            .collect();
        Self { rpcs }
    }

    pub async fn lease(&self) -> RpcClientPermit {
        let (permit, _, _) =
            futures::future::select_all(self.rpcs.iter().map(|rpc| rpc.ready().boxed())).await;
        permit
    }

    pub async fn with_retry<T>(
        &self,
        max_retries: usize,
        f: impl for<'a> Fn(&'a JsonRpcClient) -> BoxFuture<'a, anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let mut retries = 0;
        loop {
            let permit = self.lease().await;
            match f(&permit).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(err);
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub fn total_qps(&self) -> usize {
        self.rpcs.iter().map(|rpc| rpc.rate_limit).sum()
    }
}
