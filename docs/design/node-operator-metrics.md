# Meaningful Metrics for Node Operators

**Status:** Draft — for team review
**Issue:** [#3229](https://github.com/near/mpc/issues/3229)

## Problem

We need meaningful metrics and should provide node operators with recommendations on metrics to track.
Cf. [#3229](https://github.com/near/mpc/issues/3229).

## Recommendations

Chain-gateway pipeline counters, in
[`event_subscriber/metrics.rs`](../../crates/chain-gateway/src/event_subscriber/metrics.rs):

| Metric | Measures | How to interpret |
| --- | --- | --- |
| [`mpc_blocks_received_from_indexer_total`](../../crates/chain-gateway/src/event_subscriber/metrics.rs) | blocks pulled from the near-indexer stream | if the rate drops significantly, indicates starvation of the event-subscriber pipeline or an issue on the NEAR blockchain |
| [`mpc_blocks_indexed_total`](../../crates/chain-gateway/src/event_subscriber/metrics.rs) | unique blocks added to the `RecentBlocksTracker` (after dedup) | should track closely with `mpc_blocks_received_from_indexer_total`; divergence means the indexer is replaying hashes we've already seen |
| [`mpc_finalized_blocks_indexed_total`](../../crates/chain-gateway/src/event_subscriber/metrics.rs) | blocks the tracker has promoted to `Final` | should grow steadily a few seconds behind the received/indexed counters; if it freezes while those keep growing, finality is stalling |
| [`mpc_block_updates_dropped_total`](../../crates/chain-gateway/src/event_subscriber/metrics.rs) | block updates that won't be received by the node (containing signature requests, responses, etc.) | should be zero or flat. If it increases, the consumer is starved or the MPC node is not working correctly |
| [`mpc_num_fail_on_timeout_indexed`](../../crates/node/src/metrics.rs) | number of calls to `fail_on_timeout` in the MPC contract. Counts the number of failed requests (aggregate over all request types). May contain false positives if `mpc_finalized_blocks_indexed_total` diverges from `mpc_blocks_indexed_total`, as it may count transactions on non-finalized forks. | should be near zero in healthy operation. Sustained non-zero rate means the node (or the cluster) is missing the response deadline or the blockchain has a lot of forks. |

Foreign-chain RPC provider health, set once at startup (labeled by `chain`), in
[`metrics.rs`](../../crates/node/src/metrics.rs):

| Metric | Measures | How to interpret |
| --- | --- | --- |
| [`mpc_foreign_chain_rpc_providers_configured`](../../crates/node/src/metrics.rs) | RPC providers configured per foreign chain (**N**) | the denominator; changes only when the config changes |
| [`mpc_foreign_chain_rpc_providers_healthy`](../../crates/node/src/metrics.rs) | providers that passed the startup probe per foreign chain (**n**) | `n < N` usually means a typo or an API key that isn't enabled. It can also be benign: a reachable provider that can't serve the golden reference tx (unsupported chain, no reference for the current network, or a pruned non-archival provider) counts as unhealthy too, so check the logs before treating it as a hard failure |

## Recommended alerts

```promql
# Pipeline stuck (page): no blocks pulled from the indexer.
rate(mpc_blocks_received_from_indexer_total[1m]) == 0  for 5m

# Falling behind (warn): NEAR produces ~1 b/s; sustained low rate accumulates lag.
rate(mpc_blocks_received_from_indexer_total[1m]) < 0.5  for 15m

# Dropped block updates (warn): every drop is matched-event data the consumer
# will never see.
increase(mpc_block_updates_dropped_total[1m]) > 0  for 5m

# Signature timeouts (warn): the node failed to produce a signature within the
# deadline. Downstream symptom; cross-check the pipeline counters above.
increase(mpc_num_fail_on_timeout_indexed[5m]) > 0  for 5m
```
