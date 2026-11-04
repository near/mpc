# HTTP indexing

The default MPC node reads complete execution messages from an external NEAR node
through `EXPERIMENTAL_indexer_block`. It uses the same endpoint for contract views
and transaction submission. The MPC process keeps its own keyshares and request
stores; it does not initialize or run a NEAR node.

The serving node is trusted for chain state and execution data. Use an endpoint
under your operational control that supports the experimental method and retains
at least the last 250 blocks for replay. The client requires every shard in each block;
partial tracking, missing history, and inconsistent ancestry are errors.

## Configuration

Set `rpc_url` in the indexer configuration. For `start-with-config-file`:

```toml
[node.indexer]
rpc_url = "http://127.0.0.1:3030"
mpc_contract_id = "v1.signer"
finality = "optimistic"
sync_mode = "Interruption"
validate_genesis = false
concurrency = 1
```

In a launcher `user-config.toml`, the same fields belong under
`[mpc_node_config.node.indexer]`. `MPC_NEAR_RPC_URL` overrides `rpc_url` when set.
The default build requires an endpoint. Existing secrets, participant, TEE, and
signing configuration still apply; the snippet is only the indexer section.

The external NEAR node must support the RPC method with `rpc.enable_indexer_rpc`
enabled, `tracked_shards_config = "AllShards"`,
`save_tx_outcomes = true`, `save_state_changes = true`, and
`store.save_trie_changes = true`, with enough retained history for replay.
These server capabilities are separate from the MPC build, and ordinary public
RPC endpoints are not assumed to provide them. nearcore 2.14.0 serves the method
with the settings above.

HTTP indexing supports optimistic and final heads. The start position is sampled
when the indexer starts, before the first MPC job runs, so requests from then on
reach that job. `Latest` starts at the head sampled then. `Interruption` resumes
from the last persisted checkpoint and replays the 200 blocks before it to rebuild
pending requests. An explicit `Block` start follows hash ancestry to the requested
height, including skipped heights. No start reaches more than 250 blocks below the
current head: a request expires 200 blocks after the block that carried it, so
older blocks cannot produce work. Each consumer restart replays that window to
rebuild its volatile queues before scheduling new work.

Choose the restart mode deliberately:

- `Latest` always starts at the head, so requests submitted while the node was
  down are only answered by the nodes that stayed up.
- `Interruption` also answers those that have not expired yet. However long the
  node was down, it replays at most 250 blocks.

Same-height and forward fork replacements are applied with the batch that
carries them. If the serving endpoint reports a head below the last acknowledged
block, for example after failing over to a lagging node, MPC waits for the
endpoint to catch up rather than follow the lower head: its pending queues may
already have expired work at the previous height. If the endpoint is unreachable
or stalled for more than 250 blocks, the node skips to the last 250 blocks once
it recovers, as every request in the skipped blocks has expired.
`mpc_http_indexer_reanchors_total` counts these skips.

Blocks are applied in batches of at most 32. A checkpoint is published only after
a complete batch reaches all request stores and pending queues, and only when it
moved, so a long catch-up resumes from the last applied batch. Indexing does not
wait for the checkpoint to reach the disk: a background writer durably persists
the latest published checkpoint, one write at a time, so a slow disk results in
fewer, later writes rather than stalled blocks, and an older checkpoint never
replaces a newer one. The checkpoint on disk can therefore trail the applied
blocks by however long the last write took; after a restart the node only
replays a few more blocks. A stopping node waits up to 5 s for the latest
checkpoint to be written. A failed write is retried with the latest checkpoint
after 500 ms, doubling up to 10 s, and counts in
`mpc_http_indexer_checkpoint_write_failures_total`; indexing continues. Replaying an
identical request is allowed. A repeated request ID with different contents fails
closed; it is not silently overwritten while cryptographic work may still refer to
its earlier inputs. The failed MPC job restarts after a backoff of 1 s, doubling
up to 60 s while it keeps failing, and counts in
`mpc_coordinator_job_failures_total`.

Transport retries submit the same signed transaction bytes. A transaction the RPC
node queued whose effect is still unobserved after the confirmation wait counts
as `timed_out` in `mpc_outgoing_transaction_outcomes`, as with the embedded node;
one whose submission was never acknowledged counts as `unknown`. Neither proves
that the transaction will not execute later. The existing application retry
policy can still create a later transaction, so this is not an exactly-once
submission guarantee.

`validate_genesis`, `concurrency`, `wipe_near_data_token`, and `near_init` control
the embedded node and do not configure the HTTP server. HTTP applies one
acknowledged batch at a time and polls again 100 ms after reaching the head.
Deleting or editing a checkpoint is not a substitute for retaining the chain
history and MPC state needed for recovery.

## Read failures

The node retries every failed read on its own and never skips a block. A busy,
timed-out or unreachable endpoint is retried after 500 ms, doubling up to 10 s.
A block whose execution data is unavailable (`data_unavailable`) is retried the
same way for 30 s from its first failure, as an endpoint may announce a head
before saving its data.

Every other error, and unavailable data after those 30 s, is logged as an error that
names the block and the fix, retried with a backoff of up to 60 s, and counted in
`mpc_http_indexer_read_failures_total` by `error`. Such an error recurs for every
node that reads that block from a similarly configured endpoint, so the fix
belongs on the serving node:

- `limit_exceeded`: the block's indexer response exceeds the serving node's
  response cap. In nearcore 2.14 that cap is a compile-time constant of 32 MiB
  (`MAX_MESSAGE_BYTES` in `chain/jsonrpc/src/indexer.rs`), not a configuration
  setting, so serve the block from a nearcore build with a larger cap.
- `data_unavailable`, `incomplete_data`: check that the node tracks all shards,
  saves transaction outcomes and state changes, and still retains the block.
- `unsupported`: enable `rpc.enable_indexer_rpc`, `save_tx_outcomes` and
  `save_state_changes`.

See [Metrics for node operators](node-operator-metrics.md) for an alert rule.

## Embedded compatibility

Build `mpc-node` with `--features embedded-node` to retain the embedded NEAR
implementation. With that feature, omitting both endpoint settings selects the
embedded node and uses its existing initialization and synchronization settings.
An explicit endpoint still selects HTTP. Protocol, crypto, and indexer types are
shared where useful; the default node dependency graph excludes the embedded
NEAR runtime.

## Local validation

The E2E cluster can run every node against the sandbox's RPC endpoint; see
[Indexer backend](../../crates/e2e-tests/README.md#indexer-backend). The
`http_indexer` E2E tests sign across a restart of every node and answer a request
that became pending while every node was stopped.

The Docker entrypoint selects HTTP when `MPC_NEAR_RPC_URL` is set and skips
embedded NEAR initialization. The direct-image CI startup smoke test uses a local
HTTP fixture that stays syncing and verifies that the node contacts it. The
launcher smoke test does not validate production TEE behavior.
