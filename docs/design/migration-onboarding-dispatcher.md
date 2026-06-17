# Migration / onboarding dispatcher

**Status:** Design — implementation in progress.
**Issue:** #3406
**Supersedes:** #3550 (the keep-onboard-running-in-parallel approach).

## Motivation

When a node has finished onboarding once (`OnboardingJob::Done`), the migration
service today exits its loop and drops the keyshare receiver. A subsequent
back-migration (e.g. A → B → A) needs A's keyshare receiver to be alive again,
which currently requires a process restart.

#3550 attempted to fix this by keeping `onboard()` running after `Done`, parked
on a per-job cancellation token, so the same task could re-enter `Onboard(keyset)`
on a future contract transition. Review feedback from @KevinDeforth was that
running the coordinator and the onboarding loop concurrently — even with the
onboarding side dormant — leaves an implicit invariant around shared state
(`Arc<RwLock<KeyshareStorage>>`) instead of making the mutual exclusion
structural. We're taking that as the better long-term shape.

## Proposed design

A single state-driven dispatcher in mpc-node decides which subsystem runs based
on the current contract state for this node:

```rust
loop {
    match classify(&contract_state, &my_account_id) {
        Role::ActiveParticipant => run_coordinator(&cancel).await,
        Role::MayOnboard        => run_onboarding(&cancel).await,
        Role::Idle              => wait_for_state_change(&contract_state).await,
    }
}
```

`run_coordinator` and `run_onboarding` are mutually exclusive — at most one is
active at a time. The dispatcher cancels the active subsystem when the contract
state transitions out of its applicable role, then re-enters the loop.

## What this requires

- **Coordinator: cancellable and restartable.** Today `Coordinator::run` is
  effectively process-lifetime. It needs to accept a `CancellationToken` and
  return cleanly when cancelled, releasing its `Arc<RwLock<KeyshareStorage>>`
  handle and any in-flight protocol state.
- **Onboarding: terminate on `Done`.** The existing `onboard()` behavior of
  returning when reaching `Done` is the right shape under the dispatcher; the
  dispatcher takes over deciding whether to re-enter.
- **Dispatcher loop in `run.rs`** (or a new top-level module) that owns the
  watch receiver, classifies the role, and drives the cycle.

## Out of scope for this PR

- TEE attestation interaction with the dispatcher cycle — tracked separately.
- In-memory state cleanup between coordinator runs (the concern flagged in
  #3550's risk section) — see #3551.

## References

- Issue: #3406
- Slack thread with @KevinDeforth: feedback summary in PR #3550 thread.
- Superseded approach: #3550.
