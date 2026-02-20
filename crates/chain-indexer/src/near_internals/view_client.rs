use near_async::{messaging::CanSendAsync, multithread::MultithreadRuntimeHandle};
use near_client::ViewClientActorInner;
use near_indexer_primitives::{
    types::{BlockReference, Finality},
    views::BlockView,
};

use super::errors::IndexerViewClientError;

#[derive(Clone)]
pub struct IndexerViewClient {
    pub view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
}

impl IndexerViewClient {
    pub(crate) async fn latest_final_block(&self) -> Result<BlockView, IndexerViewClientError> {
        let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
        let resp = self
            .view_client
            .send_async(block_query)
            .await
            .map_err(|err| IndexerViewClientError::FinalBlockQuery {
                source: Box::new(err),
            })?;
        resp.map_err(|err| IndexerViewClientError::InvalidResponse {
            query: "final block query".to_string(),
            source: Box::new(err),
        })
    }
    pub fn send_async_view_client_query(
        &self,
        query: near_client::Query,
    ) -> Result<, IndexerViewClientError> {
        self.view_client.send_async(query)

    }
impl<A, M, R> CanSendAsync<M, R> for MultithreadRuntimeHandle<A>
where
    A: Handler<M, R> + 'static,
    M: Debug + Send + 'static,
    R: Send + 'static,
{
    fn send_async(&self, message: M) -> BoxFuture<'static, Result<R, AsyncSendError>> {
}
