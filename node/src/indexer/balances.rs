use near_sdk::AccountId;
use tokio_util::sync::CancellationToken;

use crate::{
    indexer::lib::{get_account_balance, wait_for_full_sync},
    metrics,
};

// function for monitoring signer and responder account balances
pub(crate) async fn monitor_balance(
    signer_account: AccountId,
    responder_account: AccountId,
    client: actix::Addr<near_client::ClientActor>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    cancellation_token: CancellationToken,
) {
    tracing::info!("starting balance checker",);
    wait_for_full_sync(&client).await;
    const BALANCE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    let mut interval = tokio::time::interval(BALANCE_REFRESH_INTERVAL);
    loop {
        tokio::select! {
                _ = interval.tick() => {
                   match get_account_balance(signer_account.clone(), &view_client).await {
                       Ok(balance) => {
                           tracing::info!(
                               block = balance.0, balance = balance.1, "Near signer account balance"
                           );
                           metrics::NEAR_SIGNER_BALANCE.set(balance.1);
                       }
                       Err(e) => {
                           tracing::info!("Failed to get balance for {}. Waiting for sync?", e);
                       }
                   }
                   match get_account_balance(responder_account.clone(), &view_client).await {
                       Ok(balance) => {
                           tracing::info!(
                               block = balance.0,
                               balance = balance.1,
                               "Near responder account balance",
                           );
                           metrics::NEAR_RESPONDER_BALANCE.set(balance.1);
                       }

                       Err(e) => {
                           tracing::info!("Failed to get balance for {}. Waiting for sync?", e);
                       }
                   }

                },
                _ = cancellation_token.cancelled() => { return;}
        }
    }
}
