use crate::near_internals_wrapper::traits::{HasSyncChecker, HasViewFunctionQuerier};
use crate::near_internals_wrapper::{ClientWrapper, ViewClientWrapper};

use super::traits::ContractViewer;

#[derive(Clone)]
pub struct NearContractViewer {
    client: ClientWrapper,
    view_client: ViewClientWrapper,
}

impl HasSyncChecker for NearContractViewer {
    type C = ClientWrapper;
    fn get_checker(&self) -> &Self::C {
        &self.client
    }
}
impl HasViewFunctionQuerier for NearContractViewer {
    type V = ViewClientWrapper;
    fn view_querier(&self) -> &Self::V {
        &self.view_client
    }
}

impl NearContractViewer {
    pub(crate) fn new(client: ClientWrapper, view_client: ViewClientWrapper) -> Self {
        Self {
            client,
            view_client,
        }
    }
}

impl ContractViewer for NearContractViewer {}
