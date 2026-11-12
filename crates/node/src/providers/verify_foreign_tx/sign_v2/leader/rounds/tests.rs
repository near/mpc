use super::*;
use std::assert_matches;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

const SIGNATURE: &str = "signature";
const REFUSER: ParticipantId = ParticipantId::from_raw(3);
const SILENT: ParticipantId = ParticipantId::from_raw(2);

/// A leader whose rounds end as scripted. The first asset is 0, and each retry asset counts up.
struct ScriptedRounds {
    round_results: Mutex<VecDeque<Result<&'static str, RoundFailure>>>,
    request_closes: bool,
    asset_wait: Duration,
    assets_run: Mutex<Vec<u32>>,
    avoid_sets: Mutex<Vec<BTreeSet<ParticipantId>>>,
}

impl ScriptedRounds {
    fn ending_with(round_results: Vec<Result<&'static str, RoundFailure>>) -> Self {
        Self {
            round_results: Mutex::new(round_results.into()),
            request_closes: false,
            asset_wait: Duration::ZERO,
            assets_run: Mutex::default(),
            avoid_sets: Mutex::default(),
        }
    }
}

impl LeadSigningRounds for ScriptedRounds {
    type Asset = u32;
    type Signed = &'static str;

    async fn take_retry_asset(&self, avoid: &BTreeSet<ParticipantId>) -> Result<u32, StopLeading> {
        tokio::time::sleep(self.asset_wait).await;
        if self.request_closes {
            return Err(StopLeading::RequestClosed);
        }
        let mut avoid_sets = self.avoid_sets.lock().unwrap();
        avoid_sets.push(avoid.clone());
        Ok(u32::try_from(avoid_sets.len()).unwrap())
    }

    async fn run_round(&self, asset: u32) -> Result<&'static str, RoundFailure> {
        self.assets_run.lock().unwrap().push(asset);
        self.round_results.lock().unwrap().pop_front().unwrap()
    }
}

fn refused() -> RoundFailure {
    RoundFailure::Refused(AbortedByParticipant {
        participant: REFUSER,
        reason: "the evidence does not verify".to_string(),
    })
}

fn timed_out() -> RoundFailure {
    RoundFailure::DeadlineExceeded {
        silent: BTreeSet::from([SILENT]),
    }
}

fn unattributed() -> RoundFailure {
    RoundFailure::Unattributed(anyhow::anyhow!("signature failed to verify"))
}

#[tokio::test]
async fn lead_rounds__should_retry_with_a_fresh_asset_without_the_signer_that_refused() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![Err(refused()), Ok(SIGNATURE)]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNATURE);
    assert_eq!(*leader.assets_run.lock().unwrap(), vec![0, 1]);
    assert_eq!(
        *leader.avoid_sets.lock().unwrap(),
        vec![BTreeSet::from([REFUSER])]
    );
}

#[tokio::test]
async fn lead_rounds__should_retry_without_the_silent_signers_after_a_timeout() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![Err(timed_out()), Ok(SIGNATURE)]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNATURE);
    assert_eq!(
        *leader.avoid_sets.lock().unwrap(),
        vec![BTreeSet::from([SILENT])]
    );
}

#[tokio::test]
async fn lead_rounds__should_avoid_the_failed_signers_of_every_earlier_round() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![Err(refused()), Err(timed_out()), Ok(SIGNATURE)]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNATURE);
    assert_eq!(
        *leader.avoid_sets.lock().unwrap(),
        vec![BTreeSet::from([REFUSER]), BTreeSet::from([SILENT, REFUSER])]
    );
}

#[tokio::test]
async fn lead_rounds__should_retry_after_an_unattributed_failure_without_avoiding_a_signer() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![Err(unattributed()), Ok(SIGNATURE)]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNATURE);
    assert_eq!(*leader.avoid_sets.lock().unwrap(), vec![BTreeSet::new()]);
}

#[tokio::test]
async fn lead_rounds__should_stop_after_the_third_failed_round() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![
        Err(refused()),
        Err(timed_out()),
        Err(unattributed()),
        Ok(SIGNATURE),
    ]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_matches!(
        signed,
        Err(RoundsEnd::Exhausted(RoundFailure::Unattributed(_)))
    );
    assert_eq!(*leader.assets_run.lock().unwrap(), vec![0, 1, 2]);
}

#[tokio::test]
async fn lead_rounds__should_stop_without_another_asset_after_a_local_failure() {
    // Given
    let leader = ScriptedRounds::ending_with(vec![
        Err(RoundFailure::Local(anyhow::anyhow!("no signature"))),
        Ok(SIGNATURE),
    ]);

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_matches!(signed, Err(RoundsEnd::Local(_)));
    assert!(leader.avoid_sets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lead_rounds__should_stop_when_the_request_closes_before_a_retry_asset_is_free() {
    // Given
    let leader = ScriptedRounds {
        request_closes: true,
        ..ScriptedRounds::ending_with(vec![Err(refused()), Ok(SIGNATURE)])
    };

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_matches!(signed, Err(RoundsEnd::Stopped(StopLeading::RequestClosed)));
    assert_eq!(*leader.assets_run.lock().unwrap(), vec![0]);
}

#[tokio::test(start_paused = true)]
async fn lead_rounds__should_use_up_no_round_while_waiting_for_an_asset() {
    // Given
    let leader = ScriptedRounds {
        asset_wait: Duration::from_secs(60),
        ..ScriptedRounds::ending_with(vec![Err(refused()), Err(refused()), Ok(SIGNATURE)])
    };

    // When
    let signed = lead_rounds(&leader, 0).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNATURE);
    assert_eq!(*leader.assets_run.lock().unwrap(), vec![0, 1, 2]);
}

#[test]
fn round_failure_new__should_name_the_signer_that_aborted() {
    // Given
    let error = anyhow::Error::new(AbortedByParticipant {
        participant: REFUSER,
        reason: "not an acting leader".to_string(),
    });

    // When
    let failure = RoundFailure::new(error, BTreeSet::from([SILENT]));

    // Then
    assert_eq!(failure.failed_signers(), BTreeSet::from([REFUSER]));
}

#[test]
fn round_failure_new__should_name_the_silent_signers_of_a_round_past_its_deadline() {
    // Given
    let error = anyhow::Error::new(ComputationTimeout);

    // When
    let failure = RoundFailure::new(error, BTreeSet::from([SILENT]));

    // Then
    assert_matches!(failure, RoundFailure::DeadlineExceeded { .. });
    assert_eq!(failure.failed_signers(), BTreeSet::from([SILENT]));
}

#[test]
fn round_failure_new__should_name_no_signer_for_shares_that_do_not_combine() {
    // Given
    let error = anyhow::anyhow!("signature failed to verify");

    // When
    let failure = RoundFailure::new(error, BTreeSet::from([SILENT]));

    // Then
    assert_matches!(failure, RoundFailure::Unattributed(_));
    assert!(failure.failed_signers().is_empty());
}
