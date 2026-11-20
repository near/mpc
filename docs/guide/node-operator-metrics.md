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
| `mpc_failover_leader_attempts_total` | attempts this node started as a failover leader because no response landed within the leader failover slot. Labelled by `request_type` and `rank` (1-3, how many leaders before it are presumed broken) | should stay at zero. A sustained rate means some node accepts requests as leader but fails to answer them; high ranks mean several such nodes at once. |

## Computation times

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_led_computation_duration_seconds` | how long a computation took, recorded by its leader only. Labelled by `protocol_scheme`, `task` and `outcome` (`succeeded`, `failed`, `deadline_exceeded`, `abandoned` when the caller gave up on it) | increase in the number of `failed`, `abandoned` or `deadline_exceeded` counts, and `succeeded` computations approaching the deadline for that `task`. |

## Backups

The node hands its key shares to the backup service registered for it after
every resharing, and every hour so the backup service can check its stored copy.
These gauges say whether that happened:

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_current_epoch_id` | the key epoch the contract currently holds | rises by one on every resharing. It is the reference point for the two gauges below. |
| `mpc_last_backup_served_epoch` | the last epoch this node backed up | should reach `mpc_current_epoch_id` shortly after each resharing. |
| `mpc_last_backup_served_timestamp_seconds` | when this node last served key shares to the backup service | should be under an hour old. A large gap means backups are not being taken. This only proves the node handed the shares over, not that the backup service kept them. |

## Attestation freshness

The node runs in trusted hardware and proves this by submitting an attestation
on chain. If it stops doing so, the attestation eventually expires and the
contract stops accepting signature requests until the node attests again or a
vote removes it from the participant set. These gauges tell you how much runway
is left:

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_attestation_last_landed_timestamp_seconds` | when the contract last accepted an attestation for this node, measured in NEAR block time | should be under an hour old; the node resubmits hourly. A sustained gap starts the countdown to the attestation expiring. |
| `mpc_attestation_expiry_timestamp_seconds` | when the attestation stored for this node expires, measured in NEAR block time | subtract `mpc_indexer_latest_block_timestamp_seconds` for the remaining runway. `0` means nothing is stored and the node already counts as unattested. `-1` means an attestation is stored that carries no expiry. |

## Foreign chain RPC providers

The node verifies transactions on other chains through the RPC providers you
configure under `foreign_chains`. To debug a chain, check in order:

1. [Whitelist and quorum](#whitelist-and-quorum): does the node serve the chain?
2. [The hourly probe](#the-hourly-probe): do your providers answer on the right
   network?
3. [During traffic](#during-traffic): how do they do on real requests?

Logs name a provider by its config name, metrics by a
[pseudonym](#provider-labels). Config changes need a restart.

### Whitelist and quorum

Per chain, the participants vote which RPC providers count (the whitelist) and
how many must agree (the quorum). Your provider counts when it conforms to a
whitelisted one: same host, URL, chain routing and auth. The
[TDX guide](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#whitelist-and-quorum)
has the exact rules.

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_foreign_chain_rpc_quorum_required` | gauge by `chain`: the voted quorum | the reference for the gauge below |
| `mpc_foreign_chain_rpc_providers_whitelisted` | gauge by `chain`: whitelisted providers yours conform to. Two of yours behind one count once. | below `mpc_foreign_chain_rpc_quorum_required` |

Below the quorum, the node does not register the chain with the contract and
refuses its requests. The [probe log lines](#probe-log-lines) name the provider
to fix. The gauges appear once the node is a participant, for configured chains
with a whitelist, and follow whitelist changes live.

If registration does not land, the node logs WARN
`foreign chains registration has not landed, resending; check that the node's access key allows register_foreign_chains_config`.

### The hourly probe

At startup, hourly and on each whitelist change, the node checks that each
provider serves the network in the chain's
[`expected_network_fingerprint`](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#expected-network-fingerprints).
A provider that fails stays in use. The [chain lines](#probe-log-lines) say
when that fails requests.

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_foreign_chain_rpc_providers_configured` | gauge by `chain`: configured providers, whitelisted or not | the reference for the gauge below |
| `mpc_foreign_chain_rpc_providers_healthy` | gauge by `chain`: providers that passed the latest probe | below `mpc_foreign_chain_rpc_providers_configured` |

A provider fails the probe when it:

* serves another network
* is unreachable, or silent past `timeout_sec`, in all `max_retries` attempts
* refuses the request, for example over a wrong API key
* answers with data the node cannot read
* has a token or URL the node cannot use, such as an unset `env` token

A chain without `expected_network_fingerprint` is not probed, and all its
providers count as failed.

#### Probe log lines

Each round logs WARN `foreign-chain RPC provider is unhealthy` for each failed
provider, with the reason in `status`, such as `WrongNetwork` with both
fingerprints.

Once the node has read the whitelist, each round logs how your providers differ
from it:

| Level | Message | What to do |
| --- | --- | --- |
| INFO | `foreign chain whitelist: chain is not whitelisted yet` | Nothing. Wait for the vote. |
| INFO | `foreign chain whitelist: extra provider (its host matches no whitelist entry)` | It never counts toward the quorum, but can fail requests. |
| WARN | `foreign chain whitelist: provider differs from its whitelist entry` | Fix what the `mismatch` field names: URL, chain routing or auth. One line per difference. |
| WARN | `foreign chain whitelist: two providers match the same whitelist entry` | Only the first that conforms, by config name, counts. |
| ERROR | `foreign chain whitelist: entry uses a variant this node version does not know, upgrade the node` | Upgrade the node. |
| ERROR | `foreign chain whitelist: cannot parse the on chain whitelist entry, contact the NEAR MPC team` | Contact the NEAR MPC team. |

Then it logs each unhealthy whitelisted chain in your config:

| Level | Message | What to do |
| --- | --- | --- |
| WARN | `foreign chain is below quorum: ...` | Fix the whitelist differences above. |
| WARN | `foreign chain is unhealthy: an RPC provider serves another network, so every verify request fails` | Fix or remove the `WrongNetwork` provider. |
| WARN | `foreign chain is unhealthy: too few whitelisted RPC providers passed the probe, so every verify request fails` | Fix the providers that failed. |
| WARN | `foreign chain is unhealthy: a whitelisted RPC provider did not pass the probe, the others still reach the quorum` | Fix it before another fails. |
| ERROR | `foreign chain quorum cannot be enforced: the voted quorum is zero or too large, so the node does not serve the chain` | Contact the NEAR MPC team. |

Each round ends with INFO `foreign chain probe round complete`:

| Field | What it tells you |
| --- | --- |
| `healthy`, `probed` | providers that passed, out of all configured, across chains |
| `whitelist` | `not read yet`, `matches the local config`, or the number of differences above, INFO lines included |
| `healthy_chains`, `judged_chains` | healthy chains, out of whitelisted chains in your config. A chain without `expected_network_fingerprint` that reaches the quorum is not judged, and none is until the whitelist is read. |

### During traffic

For each request it signs, the node asks every configured provider once,
whitelisted or not, and waits at most 5 seconds, with no retries.

| Metric | What it tracks | When to worry |
| --- | --- | --- |
| `mpc_foreign_chain_provider_inspection_seconds` | histogram by `chain`, `provider` and `outcome` (`answered` or `failed`): time to return | `answered` latency nearing the top bucket, the 5 second limit |
| `mpc_foreign_chain_provider_errors_total` | counter by `chain`, `provider` and `kind`: errors returned | any increase |
| `mpc_foreign_chain_provider_dropped_seconds` | histogram by `chain` and `provider`: time waited on a provider that returned nothing in 5 seconds, a dropped check. `_count` counts them. | any increase |

| `kind` | Meaning | What to do |
| --- | --- | --- |
| `unreachable` | connection failure, HTTP 5xx, 408 or 429, or rate limiting | Usually clears on its own. |
| `rejected` | refused, for example over a wrong, expired or not enabled API key | Fix the provider. |
| `malformed` | an answer the node cannot use | Fix or replace the provider. |
| `timed_out` | Aptos and Sui only, when `timeout_sec` is below 5 and the client gives up first | Treat it like `unreachable`. |

An error alone does not fail the request while the whitelisted providers that
agree still reach the quorum. A dropped check always does. On most chains it
means a slow provider.

A transaction that is not final, lacks confirmations, failed or does not exist
gives `outcome="answered"`, not an error.

Two more failures show only in logs:

| Level | Message | What to do |
| --- | --- | --- |
| WARN | `fan-out: fewer whitelisted providers reached the verdict than the quorum requires` | Check this chain's errors. |
| ERROR | `fan-out: inspectors returned mismatching verdicts` | Fix or replace the wrong provider. The line lists providers by config name, split by agreement with the first answer, so it can be on either list. |

Reading the numbers:

* Check dropped checks first, then `rejected` and `malformed`.
* Keep `outcome="failed"` out of latency percentiles.
* Series start at zero once the node is a participant, and stay flat on an
  idle node, so rely on the probe there.
* Each node counts only the requests it signs.

#### Provider labels

The `provider` label is a pseudonym that hides your RPC vendors from the
public metrics endpoint. Per chain, the node numbers your providers `p0`, `p1` and so on in
byte order of name, uppercase first: `alchemy`, `ankr` and `quicknode` become
`p0`, `p1` and `p2`, but `Ankr` would come first. Adding, removing or renaming
a provider can shift the others. Each node numbers its own.

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
# them. Signature, CKD and foreign-tx verification run under a configured 60s
# by default, and 45s is three quarters of it. Key generation and resharing are
# left out: a handful per epoch cannot support a percentile.
histogram_quantile(0.99, sum by (protocol_scheme, task, le) (
  rate(mpc_led_computation_duration_seconds_bucket{outcome="succeeded", task!~"triple_generation|key_generation|key_resharing"}[15m])
)) > 45  for 15m

# Warn: the same for triple generation, which runs under its own deadline, 120s
# by default. Splitting it out is what lets the alert above stay strict.
histogram_quantile(0.99, sum by (protocol_scheme, le) (
  rate(mpc_led_computation_duration_seconds_bucket{outcome="succeeded", task="triple_generation"}[15m])
)) > 90  for 15m

# Warn: a configured chain has a whitelist, but too few of this node's providers
# conform to it to reach the voted quorum, so the node does not serve the chain.
mpc_foreign_chain_rpc_providers_whitelisted < mpc_foreign_chain_rpc_quorum_required  for 10m

# Warn: a provider failed the hourly probe, or a chain is configured without an
# expected_network_fingerprint. It fires without traffic. The probe runs hourly,
# so the 2h hold spans at least two rounds.
mpc_foreign_chain_rpc_providers_healthy < mpc_foreign_chain_rpc_providers_configured  for 2h

# Warn: a provider refuses requests or answers with data the node cannot use.
# Causes: a wrong or expired API key, a key not enabled for the chain, or a
# broken backend. Fix the provider. Retrying does not help.
increase(mpc_foreign_chain_provider_errors_total{kind=~"rejected|malformed"}[5m]) > 0  for 10m

# Warn: a provider is unreachable, rate limited or timed out. Requests still
# succeed while the other whitelisted providers that agree reach the quorum.
# The 15m hold rides out a short burst.
increase(mpc_foreign_chain_provider_errors_total{kind=~"unreachable|timed_out"}[5m]) > 0  for 15m

# Page: a provider returned nothing within the node's 5s limit, so the request
# failed, whatever the other providers answered. A node restart during a
# request also counts one. See During traffic for what to do.
increase(mpc_foreign_chain_provider_dropped_seconds_count[5m]) > 0  for 5m

# Warn: no backup for over a day. Only meaningful once backups are being taken
# against this node. Both backup gauges read 0 after a node restart until the
# backup service's next hourly fetch, hence the 2h holds.
time() - mpc_last_backup_served_timestamp_seconds > 86400  for 2h

# Warn: a resharing happened and the new epoch has not been backed up since.
# Also fires if this node has never served a backup, because the gauge starts at 0.
mpc_last_backup_served_epoch < mpc_current_epoch_id  for 2h

# Warn: no attestation has landed in three resubmission intervals. This fires
# within hours; the expiry alerts below can fire weeks later.
mpc_indexer_latest_block_timestamp_seconds - mpc_attestation_last_landed_timestamp_seconds > 3 * 3600  for 15m

# Page: under three days of attestation runway left. The attestation expires
# with the collateral it was submitted with, so this is a backstop for the alert
# above, and also fires for a node that keeps submitting nearly stale
# collateral. `> 0` keeps the sentinel values out.
mpc_attestation_expiry_timestamp_seconds > 0
  and mpc_attestation_expiry_timestamp_seconds - mpc_indexer_latest_block_timestamp_seconds
      < 3 * 86400  for 15m

# Page: nothing is stored for this node's TLS key, so the node is out of the
# attested set. Also covers a node that never landed one.
mpc_attestation_expiry_timestamp_seconds == 0  for 15m
```

A `-1` expiry satisfies neither expiry alert, so a node holding an attestation
without an expiry is covered by the staleness alert alone.

No metric shows a foreign chain request that fails because providers disagree
or too few of them agree. If you collect logs, alert on the two log lines
in [During traffic](#during-traffic).
