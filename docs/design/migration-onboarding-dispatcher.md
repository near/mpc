# Migration / onboarding dispatcher

## Motivation

A back-migration (e.g. A → B → A — a node returning to the participant set after
having been migrated out) requires the returning node's migration service to
accept a fresh round of keyshares. The single-cycle onboarding loop, which
exits once the node reaches the active-participant state, cannot serve this
without re-initialization. To remove the process-restart requirement, the
coordinator and the onboarding subsystem are driven by an outer state-driven
dispatcher that runs them mutually exclusively and re-enters the appropriate
subsystem when the contract state transitions.

## Design

A single state-driven dispatcher in `mpc-node` selects which subsystem runs
based on the current contract state and migration info for this node:

```rust
loop {
    match classify_role(&contract_state, &migration_info, &my_id, &tls_pk) {
        Role::ActiveParticipant => run_coordinator(&cancel).await,
        Role::MayOnboard        => run_onboarding(&cancel).await,
        Role::Idle              => wait_for_state_change().await,
    }
}
```

`run_coordinator` and `run_onboarding` are mutually exclusive — at most one is
active at a time. When the contract state transitions out of the active
subsystem's role, the dispatcher cancels it and re-enters the loop with the
new role.

## Requirements

- **Coordinator: cancellable and restartable.** `Coordinator::run` takes a
  `CancellationToken` and returns cleanly when it fires, releasing its
  `Arc<RwLock<KeyshareStorage>>` handle and any in-flight protocol state.
- **Onboarding: terminate on `Done`.** The onboarding state machine returns
  when the node reaches the active-participant state. The dispatcher decides
  whether to re-enter on a subsequent transition.
- **Migration web server: process-lifetime.** The web server that accepts
  keyshare PUTs is started once and stays alive across role transitions; the
  keyshare-import receiver is cloned into each onboarding invocation so
  successive back-migrations can be served without a restart.
- **Dispatcher loop in `run.rs`** owns the contract-state and migration-info
  watch receivers, classifies the role, and drives the cycle.

## Out of scope

- TEE attestation interaction with the dispatcher cycle — tracked separately.
- In-memory state cleanup between successive coordinator runs.
