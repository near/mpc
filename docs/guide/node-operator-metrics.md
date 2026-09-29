# Metrics for node operators

The MPC node exposes Prometheus metrics on its debug port. This guide lists the
ones worth watching, what each one tells you about your node, and alert rules
you can start from.

## NEAR chain pipeline

The node watches the NEAR blockchain for incoming signature requests. These
counters tell you whether that is working:

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_blocks_received_from_indexer_total` | blocks received from the NEAR indexer stream | should roughly match NEAR block production, about one block per second. Zero for minutes means the node is cut off from the chain. |
| `mpc_blocks_indexed_total` | received blocks kept for processing, after skipping ones the node has already seen | should move together with the counter above. |
| `mpc_finalized_blocks_indexed_total` | processed blocks that reached finality on NEAR | should grow steadily a few seconds behind the two counters above. If it freezes while they keep growing, finality is stalling. |
| `mpc_block_updates_dropped_total` | block updates the node dropped, including signature requests it will never process | should stay flat. Every increase is user requests the cluster may never answer. |
| `mpc_num_fail_on_timeout_indexed` | requests the MPC contract marked as failed because no answer arrived in time | should be near zero. A sustained rate means this node, or the whole cluster, is too slow to answer. May overcount when NEAR has many forks. |

## Computation times

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_led_computation_duration_seconds` | how long a computation took, recorded by its leader only. Labelled by `protocol_scheme`, `task` and `outcome` (`succeeded`, `failed`, `deadline_exceeded`, `abandoned` when the caller gave up on it) | increase in the number of `failed`, `abandoned` or `deadline_exceeded` counts, and `succeeded` computations approaching the deadline for that `task`. |

## Backups

After every resharing, the node hands its key shares to the backup service
registered for it. These gauges say whether that happened:

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_current_epoch_id` | the key epoch the contract currently holds | rises by one on every resharing. It is the reference point for the two gauges below. |
| `mpc_last_backup_served_epoch` | the last epoch this node backed up | should reach `mpc_current_epoch_id` shortly after each resharing. |
| `mpc_last_backup_served_timestamp_seconds` | when this node last served key shares to the backup service | should be recent. A large gap means backups are not being taken. This only proves the node handed the shares over, not that the backup service kept them. |

## Attestation freshness

The node runs in trusted hardware and proves this by submitting an attestation
on chain. If it stops doing so, the contract eventually drops the node from the
participant set. These gauges tell you how much runway is left:

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_attestation_last_landed_timestamp_seconds` | when the last attestation from this node was confirmed on chain | should be under an hour old; the node resubmits hourly. A sustained gap starts the countdown to being dropped. |
| `mpc_attestation_expiry_timestamp_seconds` | when the attestation stored for this node expires, measured in NEAR block time | subtract `mpc_indexer_latest_block_timestamp_seconds` for the remaining runway. `0` means nothing is stored and the node is already out. `-1` means an attestation is stored that carries no expiry. |

## Foreign chain RPC providers

The node verifies user transactions on other chains through RPC providers you
configure. Two metric families describe them: what happens during real
verification traffic, and an hourly probe that needs no traffic.

### During traffic

Each provider gets three metrics, labeled with the `chain` (the key it is
configured under, such as `bitcoin`) and a `provider` pseudonym, so the
public metrics endpoint never shows which RPC vendors you use. The pseudonyms
are `p0`, `p1`, and so on, assigned alphabetically and case sensitively
(`Alchemy` sorts before `alchemy`): with providers `alchemy`, `quicknode`, and
`ankr`, `alchemy` becomes `p0`, `ankr` becomes `p1`, and `quicknode` becomes
`p2`. Adding, removing, or renaming a provider in the config shifts the labels after it.

| Metric | What it tracks |
| --- | --- |
| `mpc_foreign_chain_provider_inspection_seconds` | how long one provider took to return on one check, by `outcome`: `answered` or `failed` |
| `mpc_foreign_chain_provider_dropped_seconds` | checks the node stopped waiting for before the provider returned, and how long it had waited |
| `mpc_foreign_chain_provider_errors_total` | checks a provider failed to answer, counted by `kind` |

`kind` is one of:

* `unreachable`: no answer arrived: connection trouble, a 5xx, or rate
  limiting. Often clears on its own.
* `rejected`: the provider answered but refused the request. Retrying will not
  help; this needs a human.
* `malformed`: the provider answered with something the node could not use.
  Needs a human.
* `timed_out`: the provider's RPC client gave up waiting for the answer.

A dropped check is different from an error: the node itself stopped waiting,
at its deadline or at shutdown, and whether the provider ever answered is
unknown. Such checks are timed in `mpc_foreign_chain_provider_dropped_seconds`
and do not appear under any `kind`. The node waits for every provider, so
outside shutdowns one dropped check fails the whole check for that chain.

Reading the numbers:

* Error counts and dropped counts should stay at zero. Start with `rejected`
  and `malformed`, then dropped checks and `timed_out`; `unreachable` often
  clears on its own.
* For latency, filter on `outcome="answered"` and compare providers of the same
  chain with each other. To see a whole chain in one graph instead, `sum by
  (chain)` aggregates over the providers, and keeping `provider` in the `by`
  clause keeps them separate; the same works for the error counters. The top
  bucket is the deadline the node enforces, and one observation is a whole
  check (one to three RPC calls), not a single round trip. A provider drifting
  toward the top bucket is the one to watch.
* `outcome="failed"` times the checks that ended in an error, so a provider
  that fails slowly is visible. Keep it out of latency percentiles.
* For dropped checks, `rate(..._dropped_seconds_sum[5m]) /
  rate(..._dropped_seconds_count[5m])` is the average time the node waited
  before giving up. It sits near the deadline unless checks are dropped at
  shutdown.
* An answer is never an error, even when it ends the check: a transaction that
  is not final yet, has too few confirmations, was reverted, is missing, or
  sits on a block outside the canonical chain is an answer. Only failure to
  answer counts as an error.
* A provider whose answers disagree with its peers also fails the whole check
  for that chain, and these metrics do not show it: its answers count as
  answers here, since a provider that answers differently is not necessarily
  malfunctioning; it may just be slow and lag behind its peers. The node counts
  the failed check itself, labeled by chain, under
  `mpc_num_verify_foreign_tx_verdict_mismatches`, and the node logs name the
  providers that disagreed.
* Every configured provider's series appears, at zero, as soon as the node
  serves requests, and so does each configured chain's
  `mpc_num_verify_foreign_tx_verdict_mismatches`, so an idle node reports zero
  rather than nothing.
* With no traffic, all series stay flat whether providers are healthy or down.
  On a quiet node, the probe below is the health signal.
* Every participating node checks for itself: one user request produces one
  observation per provider on each node. Counts are per node, not cluster
  totals.
* Probe traffic is not counted here, so it cannot distort these numbers.

### The hourly probe

Once per hour, whether or not any traffic exists, the node asks each configured
provider which network it is serving and compares the answer with the chain's
`expected_network_fingerprint` from your config:

| Metric | What it tracks |
| --- | --- |
| `mpc_foreign_chain_rpc_providers_configured` | providers configured for the chain |
| `mpc_foreign_chain_rpc_providers_healthy` | providers that passed the latest probe |

`healthy` should equal `configured`. Anything less is a provider the probe
could not confirm: unreachable, refusing, too slow, serving a different
network, or a chain configured without an `expected_network_fingerprint`,
which the probe cannot check.

## Recommended alerts

```promql
# Page: the node receives no blocks from NEAR at all.
rate(mpc_blocks_received_from_indexer_total[1m]) == 0  for 5m

# Warn: the node receives well under one block per second and falls behind.
rate(mpc_blocks_received_from_indexer_total[1m]) < 0.5  for 15m

# Warn: block updates are being dropped. Each one is data the node will never see.
increase(mpc_block_updates_dropped_total[1m]) > 0  for 5m

# Warn: requests fail for lack of an answer in time. Cross check the pipeline counters above.
increase(mpc_num_fail_on_timeout_indexed[5m]) > 0  for 5m

# Warn: more than one computation in ten ends without a result: failed, past its
# deadline, or dropped by the caller. The last clause skips tasks with under ten
# computations in the window, so one failed key generation or resharing does not
# alert.
sum by (protocol_scheme, task) (rate(mpc_led_computation_duration_seconds_count{outcome!="succeeded"}[15m]))
  / sum by (protocol_scheme, task) (rate(mpc_led_computation_duration_seconds_count[15m])) > 0.1
  and sum by (protocol_scheme, task) (rate(mpc_led_computation_duration_seconds_count[15m])) > 0.01
  for 15m

# Warn: computations are running out of headroom against the deadline that ends
# them. Signature, presignature, CKD and foreign-tx verification run under a
# configured 60s by default, and 45s is three quarters of it. Key generation and
# resharing are left out: a handful per epoch cannot support a percentile.
histogram_quantile(0.99, sum by (protocol_scheme, task, le) (
  rate(mpc_led_computation_duration_seconds_bucket{outcome="succeeded", task!~"triple_generation|key_generation|key_resharing"}[15m])
)) > 45  for 15m

# Warn: the same for triple generation, which runs under its own deadline, 120s
# by default. Splitting it out is what lets the alert above stay strict.
histogram_quantile(0.99, sum by (protocol_scheme, le) (
  rate(mpc_led_computation_duration_seconds_bucket{outcome="succeeded", task="triple_generation"}[15m])
)) > 90  for 15m

# Warn: a provider refuses or garbles answers: a dead API key, the wrong chain,
# or a broken backend. Needs a human; retrying does not help.
increase(mpc_foreign_chain_provider_errors_total{kind=~"rejected|malformed"}[5m]) > 0  for 10m

# Warn: a provider is unreachable or rate limited while its peers on the same
# chain answer. The node tolerates this; the 15m hold rides out a short burst.
increase(mpc_foreign_chain_provider_errors_total{kind="unreachable"}[5m]) > 0  for 15m

# Page: a provider stops answering, either its RPC client timed out or the node
# gave up waiting at its deadline. The node waits for every provider, so one
# silent provider fails the check for that whole chain.
(increase(mpc_foreign_chain_provider_dropped_seconds_count[5m]) > 0
  or increase(mpc_foreign_chain_provider_errors_total{kind="timed_out"}[5m]) > 0)  for 5m

# Warn: a provider failed the hourly probe, or a chain is configured without an
# expected_network_fingerprint. Needs no traffic. The probe runs hourly, so the
# 2h hold waits for two rounds to agree.
mpc_foreign_chain_rpc_providers_healthy < mpc_foreign_chain_rpc_providers_configured  for 2h

# Warn: no backup for over a day. Only meaningful once backups are being taken
# against this node.
time() - mpc_last_backup_served_timestamp_seconds > 86400  for 1h

# Warn: a resharing happened and the new epoch has not been backed up since.
# Also fires if this node has never served a backup, because the gauge starts at 0.
mpc_last_backup_served_epoch < mpc_current_epoch_id  for 1h

# Warn: no attestation has landed in three resubmission intervals. This fires
# within hours; the expiry alerts below only fire days later.
time() - mpc_attestation_last_landed_timestamp_seconds > 3 * 3600  for 15m

# Page: under three days of attestation runway left. Backstop for the alert
# above; reached about four days after submissions stop landing. `> 0` keeps
# the sentinel values out.
mpc_attestation_expiry_timestamp_seconds > 0
  and mpc_attestation_expiry_timestamp_seconds - mpc_indexer_latest_block_timestamp_seconds
      < 3 * 86400  for 15m

# Page: nothing is stored for this node's TLS key, so the node is out of the
# attested set. Also covers a node that never landed one.
mpc_attestation_expiry_timestamp_seconds == 0  for 15m
```

A `-1` expiry satisfies neither expiry alert, so a node holding an attestation
without an expiry is covered by the staleness alert alone.
