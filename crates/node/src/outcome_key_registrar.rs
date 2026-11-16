//! Registers this node's outcome key with the contract, and again whenever the contract records
//! another key for this node's account.

use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use near_account_id::AccountId;
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::indexer::tx_sender::{TransactionProcessorError, TransactionSender};
use crate::indexer::types::ChainSendTransactionRequest;
use crate::tracking::{self, AutoAbortTask};

const MIN_RESEND_DELAY: Duration = Duration::from_secs(30);
const MAX_RESEND_DELAY: Duration = Duration::from_hours(1);

/// Must be called from a tracked task. Dropping the returned task stops the registrar.
pub(crate) fn spawn_outcome_key_registrar(
    txn_sender: impl TransactionSender + 'static,
    registered: watch::Receiver<dtos::OutcomeKeys>,
    my_account_id: AccountId,
    my_outcome_key: dtos::Ed25519PublicKey,
) -> AutoAbortTask<()> {
    tracking::spawn(
        "outcome key registrar",
        keep_outcome_key_registered(txn_sender, registered, my_account_id, my_outcome_key),
    )
}

fn resend_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(MIN_RESEND_DELAY)
        .with_max_delay(MAX_RESEND_DELAY)
        .without_max_times()
}

/// Resends a registration that has not landed after each delay of [`resend_backoff`]. The delays
/// restart once the contract records the key. Returns once the transaction processor or the
/// watched channel closes.
async fn keep_outcome_key_registered(
    txn_sender: impl TransactionSender,
    mut registered: watch::Receiver<dtos::OutcomeKeys>,
    my_account_id: AccountId,
    my_outcome_key: dtos::Ed25519PublicKey,
) {
    let mut pending: Option<PendingRegistration> = None;
    loop {
        let recorded = registered.borrow_and_update().get(&my_account_id).cloned();
        let sent = if recorded.as_ref() == Some(&my_outcome_key) {
            pending = None;
            Ok(())
        } else if let Some(registration) = &mut pending {
            registration
                .resend_if_due(&txn_sender, &my_outcome_key)
                .await
        } else {
            tracing::info!(
                outcome_key = ?my_outcome_key,
                ?recorded,
                "registering this node's outcome key"
            );
            PendingRegistration::send(&txn_sender, &my_outcome_key)
                .await
                .map(|registration| pending = Some(registration))
        };
        match sent {
            Ok(()) => {}
            Err(TransactionProcessorError::ProcessorIsClosed) => break,
        }
        tokio::select! {
            changed = registered.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            () = wait_for_resend(&pending) => {}
        }
    }
}

struct PendingRegistration {
    resends: u32,
    resend_delays: ExponentialBackoff,
    /// `None` if the next resend time overflows the clock, the registration is then not resent.
    resend_at: Option<Instant>,
}

impl PendingRegistration {
    async fn send(
        txn_sender: &impl TransactionSender,
        outcome_key: &dtos::Ed25519PublicKey,
    ) -> Result<Self, TransactionProcessorError> {
        register_outcome_key(txn_sender, outcome_key).await?;
        let mut resend_delays = resend_backoff().build();
        let delay = resend_delays.next().unwrap_or(MAX_RESEND_DELAY);
        Ok(Self {
            resends: 0,
            resend_delays,
            resend_at: resend_at_after(delay),
        })
    }

    async fn resend_if_due(
        &mut self,
        txn_sender: &impl TransactionSender,
        outcome_key: &dtos::Ed25519PublicKey,
    ) -> Result<(), TransactionProcessorError> {
        if self
            .resend_at
            .is_none_or(|resend_at| resend_at > Instant::now())
        {
            return Ok(());
        }
        self.resends = self.resends.saturating_add(1);
        let delay = self.resend_delays.next().unwrap_or(MAX_RESEND_DELAY);
        tracing::warn!(
            outcome_key = ?outcome_key,
            resends = self.resends,
            next_resend_in = ?delay,
            "outcome key registration has not landed, resending. Check that the node is an \
             attested participant and that its access key allows register_outcome_key"
        );
        register_outcome_key(txn_sender, outcome_key).await?;
        self.resend_at = resend_at_after(delay);
        Ok(())
    }
}

fn resend_at_after(delay: Duration) -> Option<Instant> {
    let resend_at = Instant::now().checked_add(delay);
    if resend_at.is_none() {
        tracing::error!(
            ?delay,
            "next outcome key registration resend time overflows the clock, not resending"
        );
    }
    resend_at
}

/// Never completes while no resend is scheduled.
async fn wait_for_resend(pending: &Option<PendingRegistration>) {
    match pending.as_ref().and_then(|pending| pending.resend_at) {
        Some(resend_at) => tokio::time::sleep_until(resend_at).await,
        None => std::future::pending().await,
    }
}

async fn register_outcome_key(
    txn_sender: &impl TransactionSender,
    outcome_key: &dtos::Ed25519PublicKey,
) -> Result<(), TransactionProcessorError> {
    txn_sender
        .send(ChainSendTransactionRequest::RegisterOutcomeKey(
            contract_args::RegisterOutcomeKeyArgs::new(outcome_key.clone()),
        ))
        .await
        .inspect_err(
            |err| tracing::warn!(error = ?err, "failed to send register outcome key transaction"),
        )
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeMap;

    use std::assert_matches;
    use tokio::sync::mpsc;

    use super::*;
    use crate::tests::common::MockTransactionSender;
    use crate::tracking::start_root_task;

    const IMMEDIATELY: Duration = Duration::ZERO;

    fn my_account_id() -> AccountId {
        "me.near".parse().unwrap()
    }

    fn my_outcome_key() -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([1; 32])
    }

    fn other_outcome_key() -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([2; 32])
    }

    fn recorded(account_id: AccountId, outcome_key: dtos::Ed25519PublicKey) -> dtos::OutcomeKeys {
        BTreeMap::from([(account_id, outcome_key)]).into()
    }

    fn registered_key(request: ChainSendTransactionRequest) -> dtos::Ed25519PublicKey {
        match request {
            ChainSendTransactionRequest::RegisterOutcomeKey(args) => args.outcome_key,
            other => panic!("expected an outcome key registration, got {other:?}"),
        }
    }

    struct Registrar {
        registered: watch::Sender<dtos::OutcomeKeys>,
        transactions: mpsc::Receiver<ChainSendTransactionRequest>,
        _task: AutoAbortTask<()>,
    }

    /// Tests run in paused time, so a wait lasts exactly until the earliest timer.
    impl Registrar {
        fn start(registered: dtos::OutcomeKeys) -> Self {
            let (registered, registered_receiver) = watch::channel(registered);
            let (sender, transactions) = mpsc::channel(10);
            let task = tracking::spawn(
                "registrar under test",
                keep_outcome_key_registered(
                    MockTransactionSender {
                        transaction_sender: sender,
                    },
                    registered_receiver,
                    my_account_id(),
                    my_outcome_key(),
                ),
            );
            Self {
                registered,
                transactions,
                _task: task,
            }
        }

        /// Returns the next registered key and the time it took to come.
        async fn next_registration(&mut self) -> (dtos::Ed25519PublicKey, Duration) {
            let started = Instant::now();
            let request = tokio::time::timeout(MAX_RESEND_DELAY * 2, self.transactions.recv())
                .await
                .expect("timed out waiting for a registration")
                .expect("transaction sender dropped");
            (registered_key(request), started.elapsed())
        }

        async fn assert_no_registration_for(&mut self, duration: Duration) {
            let received = tokio::time::timeout(duration, self.transactions.recv()).await;
            assert_matches!(received, Err(_));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_register_when_the_contract_has_no_key_for_this_node()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let registered = recorded("other.near".parse().unwrap(), my_outcome_key());

            // When
            let mut registrar = Registrar::start(registered);

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_register_when_the_contract_records_another_key() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let registered = recorded(my_account_id(), other_outcome_key());

            // When
            let mut registrar = Registrar::start(registered);

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_not_register_when_the_contract_records_the_key() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let registered = recorded(my_account_id(), my_outcome_key());

            // When
            let mut registrar = Registrar::start(registered);

            // Then
            registrar
                .assert_no_registration_for(MAX_RESEND_DELAY * 2)
                .await;
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_resend_a_registration_that_has_not_landed() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(dtos::OutcomeKeys::default());
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), MIN_RESEND_DELAY)
            );

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (my_outcome_key(), MIN_RESEND_DELAY * 2));
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_cap_the_resend_wait() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(dtos::OutcomeKeys::default());
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
            let mut delay = MIN_RESEND_DELAY;
            while delay < MAX_RESEND_DELAY {
                assert_eq!(
                    registrar.next_registration().await,
                    (my_outcome_key(), delay)
                );
                delay *= 2;
            }

            // When
            let resent = registrar.next_registration().await;

            // Then
            assert_eq!(resent, (my_outcome_key(), MAX_RESEND_DELAY));
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_stop_resending_once_the_key_lands() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(dtos::OutcomeKeys::default());
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );

            // When
            registrar
                .registered
                .send(recorded(my_account_id(), my_outcome_key()))
                .unwrap();

            // Then
            registrar
                .assert_no_registration_for(MAX_RESEND_DELAY * 2)
                .await;
        });
        root.await;
    }

    /// A resend doubles the wait. The key then lands, and the contract later records another key.
    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_register_again_with_a_fresh_wait_when_the_contract_replaces_the_key()
     {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(dtos::OutcomeKeys::default());
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), MIN_RESEND_DELAY)
            );
            registrar
                .registered
                .send(recorded(my_account_id(), my_outcome_key()))
                .unwrap();
            registrar
                .assert_no_registration_for(MIN_RESEND_DELAY / 2)
                .await;

            // When
            registrar
                .registered
                .send(recorded(my_account_id(), other_outcome_key()))
                .unwrap();

            // Then
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), MIN_RESEND_DELAY)
            );
        });
        root.await;
    }

    #[tokio::test(start_paused = true)]
    async fn keep_outcome_key_registered__should_stop_once_the_transaction_processor_closes() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given
            let mut registrar = Registrar::start(dtos::OutcomeKeys::default());
            assert_eq!(
                registrar.next_registration().await,
                (my_outcome_key(), IMMEDIATELY)
            );

            // When
            drop(registrar.transactions);

            // Then
            let stopped =
                tokio::time::timeout(MIN_RESEND_DELAY * 2, registrar.registered.closed()).await;
            assert_matches!(stopped, Ok(()));
        });
        root.await;
    }
}
