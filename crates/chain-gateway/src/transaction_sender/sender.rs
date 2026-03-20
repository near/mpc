use near_account_id::AccountId;
use near_indexer_primitives::types::Gas;

use crate::{
    ChainGateway,
    errors::ChainGatewayError,
    transaction_sender::{
        TransactionSigner,
        traits::{SubmitFunctionCall, SubmitTransaction},
    },
};

#[derive(derive_more::Constructor)]
pub struct TransactionSender {
    chain_gateway: ChainGateway,
    signer: TransactionSigner,
}

impl SubmitTransaction for TransactionSender {
    type Error = ChainGatewayError;
    async fn submit(
        &self,
        receiver_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
        gas: Gas,
    ) -> Result<(), ChainGatewayError> {
        self.chain_gateway
            .submit_function_call_tx(
                &self.signer,
                receiver_id,
                method_name.to_string(),
                args,
                gas,
            )
            .await?;
        Ok(())
    }
}
