use crate::near_internals_wrapper::traits::{
    HasLatestFinalBlockInfoFetcher, HasSignedTransactionSubmitter,
};
use crate::near_internals_wrapper::{RpcHandlerWrapper, ViewClientWrapper};

#[derive(Clone)]
pub struct NearTransactionSubmitter {
    rpc_handler: RpcHandlerWrapper,
    view_client: ViewClientWrapper,
}

impl HasLatestFinalBlockInfoFetcher for NearTransactionSubmitter {
    type F = ViewClientWrapper;
    fn fetcher(&self) -> &Self::F {
        &self.view_client
    }
}
impl HasSignedTransactionSubmitter for NearTransactionSubmitter {
    type S = RpcHandlerWrapper;
    fn submitter(&self) -> &Self::S {
        &self.rpc_handler
    }
}

impl NearTransactionSubmitter {
    pub(crate) fn new(rpc_handler: RpcHandlerWrapper, view_client: ViewClientWrapper) -> Self {
        Self {
            rpc_handler,
            view_client,
        }
    }
}
