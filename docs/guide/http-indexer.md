# HTTP indexing

The default MPC node reads complete execution messages from an external NEAR node
through `EXPERIMENTAL_indexer_block`. It uses the same endpoint for contract views
and transaction submission. The MPC process keeps its own keyshares and request
stores; it does not initialize or run a NEAR node.

The serving node is trusted for chain state and execution data. Use an endpoint
under your operational control that supports the experimental method and retains
the history needed for replay. The client requires every shard in each block;
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
These server capabilities are separate from the MPC build.
Ordinary public RPC endpoints are not assumed to provide them. Use a server
build containing nearcore [#16404](https://github.com/near/nearcore/pull/16404),
[#16405](https://github.com/near/nearcore/pull/16405), and
[#16407](https://github.com/near/nearcore/pull/16407); the MPC build does not add
these capabilities to an older NEAR release.

HTTP indexing supports optimistic and final heads. `Latest` initially processes
the sampled head. `Interruption` resumes from the acknowledged checkpoint, with
additional history to rebuild pending requests. An explicit `Block` start follows
hash ancestry to the requested height, including skipped heights. Each consumer
restart rebuilds its volatile queues before scheduling new work.

Same-height and forward fork replacements are applied as complete batches. MPC
stops if the serving endpoint moves to a lower height: its pending queues may
already have expired work at the previous height. It does not silently continue
with an incomplete request window. The reusable indexer client and block tracker
can represent lower heads, but automatic MPC recovery from them is not enabled.

A checkpoint is written only after the complete batch reaches all request stores
and pending queues. Replaying an identical request is allowed. A repeated request
ID with different contents fails closed; it is not silently overwritten while
cryptographic work may still refer to its earlier inputs.

Transport retries submit the same signed transaction bytes. HTTP queueing does
not establish execution; an unobserved effect remains unknown. The existing
application retry policy can still create a later transaction, so this is not an
exactly-once submission guarantee.

`validate_genesis`, `concurrency`, `wipe_near_data_token`, and `near_init` control
the embedded node and do not configure the HTTP server. HTTP consumes one
acknowledged batch at a time, polling again 100 ms after successful processing.
Transient read failures retain the separate 500 ms initial retry delay. Deleting or editing a checkpoint is not a substitute
for retaining the chain history and MPC state needed for recovery.

## Embedded compatibility

Build `mpc-node` with `--features embedded-node` to retain the embedded NEAR
implementation. With that feature, omitting both endpoint settings selects the
embedded node and uses its existing initialization and synchronization settings.
An explicit endpoint still selects HTTP. Protocol, crypto, and indexer types are
shared where useful; the default node dependency graph excludes the embedded
NEAR runtime.

## Local validation

The [focused E2E test](../../crates/e2e-tests/README.md#local-http-indexer-comparison)
starts three real MPC processes and independently verifies threshold signatures.
It uses local mock attestation. The test can compare the embedded and HTTP paths
against the same sandbox and contract artifacts.

The Docker entrypoint selects HTTP when `MPC_NEAR_RPC_URL` is set and skips
embedded NEAR initialization. The direct-image CI startup smoke test uses a local
HTTP fixture that stays syncing and verifies that the node contacts it. Full
signing and recovery use the real-node E2E test above. The launcher smoke test
checks the candidate launcher against its pinned released node image; it does
not validate a candidate HTTP node deployment or production TEE behavior.
