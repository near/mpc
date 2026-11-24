use std::{fmt::Debug, time::Duration};

use anyhow::anyhow;
use near_contract_transport::WatchContractState;
use near_mpc_contract_interface::types::DestinationNodeInfo;
use tokio_util::sync::CancellationToken;

use crate::{backup::put_keyshares, ports};

/// Sends the stored keyshares to the account's migration destination as soon as one is observed,
/// and again after each given retry [`Duration`] while it stays, until the given
/// [`CancellationToken`] is cancelled. Fails only when the destination can no longer be watched.
pub async fn run_recovery(
    mpc_nodes: &impl ports::P2PClient,
    keyshares_storage: &impl ports::KeyShareRepository,
    mut destination: impl WatchContractState<Value = Option<DestinationNodeInfo>, ViewError: Debug>,
    retry_delay: Duration,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let has_destination = match destination.latest() {
            Ok(observed) => observed.value.is_some(),
            Err(err) => {
                tracing::error!(
                    ?err,
                    "could not read the account's migration destination, waiting for change"
                );
                false
            }
        };
        if has_destination {
            match put_keyshares(mpc_nodes, keyshares_storage).await {
                Ok(()) => tracing::info!("sent keyshares to the migration destination"),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "failed to send keyshares to the migration destination"
                    );
                }
            }
        }

        // Sent again even after a success: the destination may lose the keyshares, e.g. to a
        // restart, before it concludes the migration
        tokio::select! {
            observed = destination.changed() => observed
                .map_err(|err| anyhow!("stopped observing the migration destination: {err:?}"))?,
            () = tokio::time::sleep(retry_delay), if has_destination => {}
            () = shutdown.cancelled() => return Ok(()),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_contract_transport::mock::{MockViewContract, observed};
    use near_mpc_contract_interface::types::Ed25519PublicKey;
    use rstest::rstest;
    use tokio_util::sync::CancellationToken;

    use super::run_recovery;
    use crate::test_utils::{
        FakeKeyshareStorage, FakeP2PClient, TEST_RETRY_DELAY, keyshares_for, migration_destination,
        mpc_contract, operator_account_id,
    };

    #[rstest]
    #[case::destination_stays(true, true, 3)]
    #[case::migration_concludes(true, false, 1)]
    #[case::migration_starts(false, true, 2)]
    #[tokio::test(start_paused = true)]
    async fn run_recovery__should_send_keyshares_while_its_account_has_a_destination(
        #[case] listed_at_start: bool,
        #[case] listed_after_half_a_retry_delay: bool,
        #[case] expected_sends: usize,
    ) {
        // Given
        let mpc_nodes = FakeP2PClient::new();
        let storage = FakeKeyshareStorage::with_keyshares(keyshares_for(1, &[0]));
        let destination = |listed: bool| {
            observed(&listed.then(|| migration_destination(Ed25519PublicKey::from([2; 32]))))
        };
        let contract = MockViewContract::new(destination(listed_at_start));
        let watched_destination = mpc_contract(contract.clone())
            .attested_migration_destination(operator_account_id())
            .subscribe()
            .await;
        let shutdown = CancellationToken::new();

        // When
        let change_the_destination_then_stop = async {
            tokio::time::sleep(TEST_RETRY_DELAY / 2).await;
            contract.set_response(destination(listed_after_half_a_retry_delay));
            // Sends fall on whole and half retry delays, so stopping between them cannot race one
            tokio::time::sleep(TEST_RETRY_DELAY * 7 / 4).await;
            shutdown.cancel();
        };
        let (result, ()) = tokio::join!(
            run_recovery(
                &mpc_nodes,
                &storage,
                watched_destination,
                TEST_RETRY_DELAY,
                shutdown.clone(),
            ),
            change_the_destination_then_stop,
        );

        // Then
        result.unwrap();
        assert_eq!(mpc_nodes.put_keyshares_calls(), expected_sends);
    }
}
