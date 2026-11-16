use super::*;
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, outcome_signing_key, signed_by_its_signer,
};
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
use std::assert_matches;

const SIGNER: ParticipantId = ParticipantId::from_raw(1);
const OTHER: ParticipantId = ParticipantId::from_raw(2);
const YIELD: YieldId = YieldId([9; 32]);
const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);
const NOT_FOUND: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Negative(
    ForeignTxVerificationNegativeVerdict::TransactionNotFound,
));

fn signed(yield_id: YieldId, signer: ParticipantId, outcome: NodeOutcome) -> SignedNodeOutcome {
    signed_by_its_signer(NodeOutcomeStatement {
        yield_id,
        signer,
        outcome,
    })
}

fn store() -> NodeOutcomes {
    let store = NodeOutcomes::new();
    store.set_outcome_keys(outcome_public_keys(&[SIGNER, OTHER]));
    store
}

fn indexed_store() -> NodeOutcomes {
    let store = store();
    store.index([YIELD]);
    store
}

fn kept(store: &NodeOutcomes) -> Vec<NodeOutcomeStatement> {
    store
        .outcomes_of(YIELD)
        .iter()
        .map(|outcome| outcome.statement().clone())
        .collect()
}

fn statement(signer: ParticipantId, outcome: NodeOutcome) -> NodeOutcomeStatement {
    NodeOutcomeStatement {
        yield_id: YIELD,
        signer,
        outcome,
    }
}

#[test]
fn node_outcomes_receive__should_keep_a_verified_outcome_of_an_indexed_yield() {
    // Given
    let store = indexed_store();

    // When
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // Then
    assert_eq!(kept(&store), vec![statement(SIGNER, VERIFIED)]);
}

#[test]
fn node_outcomes_receive__should_reject_a_bad_signature() {
    // Given
    let store = indexed_store();
    let forged = outcome_signing_key(OTHER)
        .sign(statement(SIGNER, VERIFIED))
        .unwrap();

    // When
    let result = store.receive(SIGNER, forged);

    // Then
    assert_matches!(
        result,
        Err(RejectedNodeOutcome::Verification(
            NodeOutcomeVerificationError::BadSignature
        ))
    );
    assert_eq!(kept(&store), vec![]);
}

#[test]
fn node_outcomes_receive__should_reject_an_outcome_relayed_by_another_sender() {
    // Given
    let store = indexed_store();

    // When
    let result = store.receive(OTHER, signed(YIELD, SIGNER, VERIFIED));

    // Then
    assert_matches!(
        result,
        Err(RejectedNodeOutcome::SignedByAnother {
            from: OTHER,
            signer: SIGNER
        })
    );
    assert_eq!(kept(&store), vec![]);
}

#[test]
fn node_outcomes_receive__should_keep_one_statement_per_signer() {
    // Given
    let store = indexed_store();
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // When
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // Then
    assert_eq!(kept(&store), vec![statement(SIGNER, VERIFIED)]);
}

#[test]
fn node_outcomes_receive__should_keep_both_statements_of_a_conflicting_signer() {
    // Given
    let store = indexed_store();
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // When
    store
        .receive(SIGNER, signed(YIELD, SIGNER, NOT_FOUND))
        .unwrap();

    // Then
    assert_eq!(
        kept(&store),
        vec![statement(SIGNER, VERIFIED), statement(SIGNER, NOT_FOUND)]
    );
}

#[tokio::test(start_paused = true)]
async fn node_outcomes_index__should_count_an_outcome_that_arrived_before_the_request() {
    // Given
    let store = store();
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();
    tokio::time::advance(UNINDEXED_OUTCOME_LIFETIME - Duration::from_millis(1)).await;

    // When
    store.index([YIELD]);

    // Then
    assert_eq!(kept(&store), vec![statement(SIGNER, VERIFIED)]);
}

#[tokio::test(start_paused = true)]
async fn node_outcomes_index__should_drop_an_outcome_kept_unindexed_for_too_long() {
    // Given
    let store = store();
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();
    tokio::time::advance(UNINDEXED_OUTCOME_LIFETIME).await;

    // When
    store.index([YIELD]);

    // Then
    assert_eq!(kept(&store), vec![]);
}

#[tokio::test(start_paused = true)]
async fn node_outcomes_receive__should_cap_the_unindexed_yields_per_sender() {
    // Given
    let store = store();
    let yield_of = |index: usize| {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&index.to_le_bytes());
        YieldId(id)
    };
    for index in 0..MAX_UNINDEXED_YIELDS_PER_SENDER {
        store
            .receive(SIGNER, signed(yield_of(index), SIGNER, VERIFIED))
            .unwrap();
    }
    let over_the_cap = yield_of(MAX_UNINDEXED_YIELDS_PER_SENDER);

    let forged = outcome_signing_key(OTHER)
        .sign(NodeOutcomeStatement {
            yield_id: over_the_cap,
            signer: SIGNER,
            outcome: VERIFIED,
        })
        .unwrap();

    // When
    let forged_over_the_cap = store.receive(SIGNER, forged);
    let from_the_same_sender = store.receive(SIGNER, signed(over_the_cap, SIGNER, VERIFIED));
    let from_another_sender = store.receive(OTHER, signed(over_the_cap, OTHER, VERIFIED));
    tokio::time::advance(UNINDEXED_OUTCOME_LIFETIME).await;
    let after_the_others_expired = store.receive(SIGNER, signed(over_the_cap, SIGNER, VERIFIED));

    // Then
    assert_matches!(
        forged_over_the_cap,
        Err(RejectedNodeOutcome::TooManyUnindexedYields(SIGNER))
    );
    assert_matches!(
        from_the_same_sender,
        Err(RejectedNodeOutcome::TooManyUnindexedYields(SIGNER))
    );
    from_another_sender.unwrap();
    after_the_others_expired.unwrap();
}

#[test]
fn node_outcomes_forget__should_drop_the_outcomes_of_a_settled_yield() {
    // Given
    let store = indexed_store();
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // When
    store.forget(&[YIELD]);

    // Then
    assert_eq!(kept(&store), vec![]);
}

#[tokio::test]
async fn node_outcomes_changed__should_complete_once_an_outcome_is_kept() {
    // Given
    let store = indexed_store();
    let changed = store.changed();
    tokio::pin!(changed);
    changed.as_mut().enable();

    // When
    store
        .receive(SIGNER, signed(YIELD, SIGNER, VERIFIED))
        .unwrap();

    // Then
    tokio::time::timeout(Duration::from_secs(5), changed)
        .await
        .unwrap();
}

#[tokio::test]
async fn follow_outcome_keys__should_rebuild_the_keys_on_each_change_of_the_registered_keys() {
    // Given
    let account: dtos::AccountId = "signer.near".parse().unwrap();
    let participants = ParticipantsConfig {
        threshold: 1,
        participants: vec![crate::config::ParticipantInfo {
            id: SIGNER,
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key(),
            near_account_id: account.clone(),
        }],
    };
    let registered_key = dtos::Ed25519PublicKey::from(
        &ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key(),
    );
    let registered: dtos::OutcomeKeys = BTreeMap::from([(account, registered_key)]).into();
    let (sender, receiver) = watch::channel(dtos::OutcomeKeys::default());
    let store = Arc::new(NodeOutcomes::new());
    let following = tokio::spawn(follow_outcome_keys(
        store.clone(),
        participants.clone(),
        receiver,
    ));

    // When
    sender.send(registered.clone()).unwrap();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), following)
        .await
        .unwrap()
        .unwrap();

    // Then
    assert_eq!(
        *store.outcome_keys(),
        OutcomePublicKeys::new(&participants, &registered)
    );
    assert_ne!(*store.outcome_keys(), OutcomePublicKeys::default());
}
