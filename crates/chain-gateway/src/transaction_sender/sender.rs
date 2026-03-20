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
    ) -> Result<(), ChainGatewayError> {
        const MAX_GAS: Gas = Gas::from_teragas(300);
        self.chain_gateway
            .submit_function_call_tx(
                &self.signer,
                receiver_id,
                method_name.to_string(),
                args,
                MAX_GAS,
            )
            .await?;
        Ok(())
    }
}
