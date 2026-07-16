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
based on the current contract state and migration info for this node. Role
classification is `OnboardingJob::new(migration_info, contract_state, my_id,
tls_pk)`:

```rust
loop {
    match OnboardingJob::new(&migration_info, &contract_state, &my_id, &tls_pk) {
        OnboardingJob::Done => {
            // Active participant.
            select! {
                _ = coordinator.run() => { ... }
                _ = wait_until_role_change(..., Done) => { /* drop coordinator */ }
            }
        }
        OnboardingJob::Onboard(_) | OnboardingJob::WaitForStateChange => {
            // Returns on the next `Done`.
            onboard(...).await?;
        }
    }
}
```

The coordinator and onboarding are mutually exclusive — at most one is active
at a time. When the contract state transitions away from `Done`, the
dispatcher drops the coordinator future; cleanup of in-flight MPC tasks
cascades through the `drop_guard` on the coordinator's internal cancellation
token. The coordinator's own fields (`Arc<RwLock<KeyshareStorage>>`,
`SecretDB`, etc.) stay allocated across role changes because the dispatcher
holds the `Coordinator` by `&mut`.

## Requirements

- **Coordinator: re-entrant by drop.** `Coordinator::run` takes `&mut self`
  so the dispatcher can swap it in and out across role changes. Dropping the
  future stops the in-flight MPC runtime and spawned tasks via the
  `drop_guard` on its internal cancellation token; the coordinator's owned
  state is preserved for the next run.
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
