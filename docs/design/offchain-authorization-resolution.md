# Authorization Resolution for Off-chain Signature Requests

**Status:** draft for discussion · **Author:** Haiyue Chen (with Claude) · **Date:** 2026-08-17

## Summary

Two separate things meet here.

1. **NEP-641** is an authorization standard. A contract answers one question through a view
   function, `w_resolve_auth`: does this account authorize this payload? An answer can point
   at further authorizations, which is how multisigs, extensions and delegated wallets all
   work through the same interface. Full spec:
   [near/NEPs/neps/nep-0641.md](https://github.com/near/NEPs/blob/master/neps/nep-0641.md).

2. The off-chain request flow takes signature requests
   straight from a client instead of reading them off the chain. Those requests are
   authorized under NEP-641, so every node has to resolve them itself.

The problem is where they meet. When a request arrives as a transaction, the chain does
the hard part for us: every node reads the same request from the same place, and the
block it landed in is the obvious one to resolve against. An off-chain request arrives
with none of that, and the nodes still have to resolve it against state fresh enough for
the timestamp rule (NEP-641), and agree on the answer.

We can achieve off-chain requests without tracking a new shards or trusted RPC providers:

- A client, meaning a wallet, dApp, or backend service, sends its signed message to a
  **relay service** we run.
- The relay asks a **witness provider** (an ordinary full node with one extra endpoint) to
  resolve the authorization at its latest final block. The provider records
  every piece of state the resolution read, with proofs tying each piece to that block.
- Each MPC node redoes the resolution itself, checking that state against headers the
  neard it already embeds has validated.
- Every MPC then works from the same block, named in the request, so everyone reaches the same
  answer.

---

## Problem statement

Resolving `w_resolve_auth` is difficult for our MPC network:

1. **Arbitrary contracts.** The request may name any contract, they sit on any shard, and resharding
   moves accounts between shards.
2. **RPC providers cannot be trusted.** RPC providers could be malicious, the view call response comes with no proofs.
   An honest provider can also lag behind the chain, so its response may be stale.
3. **Determinism.** Nodes resolving at their own latest block may disagree when an
   authorization contract change happens.
4. **Recursion.** A multisig account sends us to its members, who may be contracts with
   conditions of their own. The request never says how deep it goes, and the chain is
   built by contracts we do not trust, so we need to cap depth and breadth.

---

## Architecture

Client to relay, relay to MPC network, with the witness provider and header feed hanging
off that. Only the chain is trusted: nodes re-verify everything the relay and provider hand
over, so the worst either can do is fail to answer.

![Overview: the client signs and sends to the relay; the relay fetches a witness bundle from an untrusted full node at final block B, announces the request to entry nodes and serves the bundle by hash; every node verifies the request and walks the authorization tree itself; the presignature's set signs and the leader posts the result back.](diagrams/overview.png)

**Step 1: the client signs and submits.** A plain NEP-641 message over HTTPS.

![Step 1: the client sends a signed NEP-641 message to the relay over HTTPS.](diagrams/step1.png)

**Step 2: the relay requests a witness.** A provider resolves the authorization at its
latest final block, call it B, with storage recording on, and reports which block it used.

![Step 2: the relay calls witness_view_call on an untrusted full node that is fully synced with the NEAR chain.](diagrams/step2.png)

**Step 3: the provider returns the bundle.** Every state entry the walk touched, contract
code, non-inclusion proofs for what was missing, and Merkle proofs tying it all to B.

![Step 3: the witness provider returns a bundle of state entries, contract code, absence proofs, and Merkle proofs to the relay.](diagrams/step3.png)

**Step 4: the relay injects the request.** It pushes an announcement, carrying the NEP-641 message,
its signature, the block B hash and the bundle hash, to k entry nodes that hold direct
connections to the relay. The entry nodes broadcast the message over the mesh. If the bundle is small, it will ride along inside the announcement. A large one is fetched by each node by hash separately.

![Step 4: the relay pushes a signed announcement to k rotating entry nodes, which pass it over the MPC mesh; the bundle travels inside the announcement when small, and is fetched by hash when not.](diagrams/step4.png)

**Step 5: Selected leader starts, and the participants each verifies for itself.** Every node now
holds the request, similar to on-chain requests today, a leader node is elected by computing a hash of the request. The leader takes one of its presignatures and opens a session with that presignature's participant set. Each of the participants then verifies the request (Component 6) and walks the authorization tree before signing a share.
A participant that rejects tells that to the leader node, so the leader aborts at
once and retries (Component 7).

![Step 5: the leader, chosen by request hash, verifies first, then takes a presignature and opens a session with that presignature's exact participant set; each verifies the request, and all accepting produces a threshold signature while any rejection aborts the attempt at once so the leader can retry.](diagrams/step5.png)

**Step 6: the leader posts the result.** `POST /result/<request_hash>`, an outbound call
like the bundle fetch, and the relay answers the client.

![Step 6: the leader posts the signature to the relay instance named in the announcement, an outbound call needing no held stream, and the relay answers the client.](diagrams/step6.png)

### Component 1: the relay (we implement and run)

The relay has four jobs: take the request, get a witness bundle, inject the request into the
MPC network, and return the answer.

**Take the request.** `POST /sign` accepts a signed message carrying a NEP-641 payload. It
returns the signature if one arrives within a few seconds, or HTTP 202 and a handle if the signature could not be generated quickly.

The handle is the signed message's hash, which the client can compute.
`GET /result/<message_hash>` returns the latest result for that message, and servers can
register a callback instead of polling.

Signing is not idempotent. Sending the same payload twice runs it twice and yields two
different but equally valid signatures, each costing a presignature. The result endpoint
holds only the most recently completed one.

**Get a witness bundle.** The relay asks a witness provider to resolve the NEP-641
authorization at its latest final block. The provider returns a witness bundle, which contains the block it used and other information, details in Component 3. The bundle then travels to the MPC nodes, inlined in the Relay to entry node message when small, or fetched by the nodes using bundle_hash when too big. Each node verifies the bundle locally (component 6).

A set of witness providers are supplied through config at launch, and the relay fails over on error, timeout, or a
block too old. The set of providers needs no trust since every node re-verifies the proofs. A bad provider only
costs a retry.

**Inject the request.** Relay pushes a signed announcement to the k entry nodes that hold
connections to it, carrying the bundle inline when small, or served at
`GET /bundle/<bundle_hash>` when too big.

Three hashes appear from here on, so to keep them apart: `message_hash` identifies the
client's signed message, `bundle_hash` identifies the bundle, and `request_hash` covers the
whole `WitnessedSignatureRequest` (message, block reference and bundle together) and is what
binds a signing session.

**Return the answer.** The session leader posts the finished signature, which the relay
verifies against the MPC network's public key before answering the waiting client or filling
the handle.

Rejections are silent today. That is survivable on chain, where the requester is already
waiting on blocks, but off-chain clients expect faster responses, so failing fast
is an UX requirement. A node that rejects should signify to the leader why. It lets the leader and the relay give up as soon as the rejection is clearly deterministic and unanimous across all participants.

**The relay is trusted with nothing.** Nodes verify everything it sends, so it cannot forge
a request. However, the Relay being the only way in it can censor or delay requests, and we accept that risk. This is an off-chain path, so this risk is unavoidable. In this design the worst a compromised or failing relay can do is degrade or stop off-chain signing. It can never produce a wrong signature. Running redundant Relay instances helps us reduce that risk.

### Component 2: the witness provider (untrusted)

A program that owns a NEAR full node tracking every shard, and exposes a `witness_view_call` endpoint that does
not exist anywhere today. It is also the only RPC-shaped thing in the design.

It has three jobs:

1. resolve the authorization at a recent final block
2. record every piece of state that resolution reads
3. prove those pieces belong to that block.

```
witness_view_call(signed_message) -> WitnessBundle
```

The response type `WitnessBundle` is explained further in component 3.

**Resolving.** It runs the view call at its own latest final
block and reports the block height back.

**What "at block B" means here** An RPC query at B
returns the state _after_ B's work ran, but a header only publishes a fingerprint of the
state _before_ it; the post-state fingerprint reaches the chain in the next block carrying
work for that shard. Proving against the post-state would therefore need two blocks, so this
design uses the fingerprint in B itself, and "at block B" means the state as it stood just
before B. That gives up about a second of freshness for a proof needing nothing but B. The
provider and the nodes must make the same choice or every proof fails, on valid requests,
which is the worst kind of failure to debug. (In nearcore terms,
`inner_lite.prev_state_root` rather than `chunk_extra.state_root()`.)

A shard that stops producing chunks stops advancing its fingerprint while block timestamps
keep moving, so B can look fresh while the shard hosting the contract is minutes stale. MPC
nodes see that from the shard's last chunk and reject when the gap exceeds the recency
window.

**Recording.** As a contract runs it reads entries out of the chain's stored data. nearcore's
_storage recording_ keeps a copy of every entry read, together with the chain of hashes that
ties that entry back to the single fingerprint the block publishes for all state. Anyone
holding those copies can check that each entry really came from that block and was not
altered. None of this is new machinery: validators already use it to check a chunk's work
without keeping the state themselves, which is what
[NEP-509 stateless validation](https://github.com/near/NEPs/blob/master/neps/nep-0509.md)
introduced (see also [validators](https://docs.near.org/protocol/network/validators)).

**Proving.** The bundle makes two kinds of claims:

1. At block B certain storage keys held certain values
2. At block B certain accounts or keys were not there at all.
   A node holding no state for those shards has to check both without trusting the provider.

What makes that possible is how NEAR stores state. Each shard's state is arranged as a Merkle
trie, in which every node is named by the hash of its contents, so a parent's hash covers its
children and the hash at the root is a fingerprint of that shard's entire state.

![Structure: the block header at B carries one fingerprint over every shard's state root. Shard 1's state root is the top of that shard's Merkle trie, and the path down through its trie nodes reaches the storage key and value the resolution read. The branches to either side are not needed and are not in the bundle.](diagrams/proof-structure.png)

So a proof is a set of trie nodes. To prove a value the resolution read,
the provider keeps the nodes along the path from the state root down to it. To prove a key
was absent, it keeps the path down to the point where that key would have branched off,
showing no such child exists. Storage recording notes down the trie nodes being touched while the witness provider executes contract code.

This only proves what was the blockchain state held by the witness provider at block B. It
says nothing about which entries the contract code actually read, nor that the provider's claimed
answer follows from them. A dishonest provider could ship valid proofs alongside a
fabricated result. The proofs make the ingredients trustworthy, replaying the resolution on
each MPC node makes the answer trustworthy (Component 6). Neither half is enough on its own.

Those trie paths stop at the shard's state root, which on its own is just a number the
witness provider handed over. The block header carries a fingerprint of every shard's state
root together, and each MPC node validates headers itself rather than taking them from the
bundle. So the bundle includes one last path, from this shard's root up into that
fingerprint, and a node checks every proof against a header it already trusts (Component 5).

![Proof chain: the value read, or the gap where an absent key would sit, hashes up through the trie nodes on its path to the shard's state root, then through a path over all shard roots, landing on the block header at B, which the node validated itself. Everything except the header travels in the witness bundle.](diagrams/proof-chain.png)

Further reading: [block structure](https://nomicon.io/DataStructures/Block) for what a
header commits to, [trie storage](https://github.com/near/nearcore/blob/master/docs/architecture/storage/trie_storage.md)
for how state is stored and proved, and [the light client
spec](https://nomicon.io/ChainSpec/LightClient) for verifying headers without running a
node.

**Who runs a witness provider.**
At launch we run the witness provider ourselves.

The hardware requirement is ordinary: a machine running a full near node tracking current state for all shards,
which RPC providers, exchanges and indexer operators run routinely.

The software does not exist, no public RPC provider would record a view call and prove it. Building it looks tractable and needs
no change to nearcore, but we need to align with the nearcore team early on 2 questions:
1. Would they ship the endpoint in `neard` itself, so any full node could serve it by upgrading? 
2. If not, we build it on crates they mark internal (`node-runtime`, `near-store`, `near-epoch-manager`, all `publish = false`), and we need to
know what stability we can expect from them. 

Building `witness_view_call`, at the end of this document expands on requirements for this.


### Component 3: the witness bundle

Everything a MPC node needs to redo the resolution itself while holding no state for the shards
involved.

```
WitnessBundle {
  block_hash: CryptoHash,                 // the block everything resolved at,
                                          // always the provider's latest final block
  result: Result<String, String>,         // the payload the walk authorized, or
                                          // the failure that stopped it; advisory
                                          // only, since nodes recompute it
  shard_witnesses: Vec<{                  // one entry per shard the walk visited
    shard_id: ShardId,
    state_root: CryptoHash,               // this shard's root at block B
    recorded_trie_nodes: PartialState,    // every storage node the walk
                                          // touched in this shard, proving each
                                          // value present or absent
    merkle_path_to_header: MerklePath,    // this root's place among
                                          // all shards, up to the block header
  }>,
  contract_code: HashMap<CryptoHash, Vec<u8>>,  // one entry per distinct
                                                // implementation the walk ran
  execution_context: {                    // everything the contracts can observe
    block_height: BlockHeight,
    block_timestamp: u64,                 // nanoseconds
    prev_block_hash: CryptoHash,
    epoch_id: EpochId,
    epoch_height: EpochHeight,
    protocol_version: ProtocolVersion,    // selects the runtime rules in force
  },
}
```

A contract can read every field of the execution context, so the provider and the nodes must
run with identical values or produce different answers for reasons unrelated to
authorization. They are block-level, so one context covers every call in the walk. Two things
are deliberately absent: the shard each call runs on, which follows from the account and the
epoch's shard layout, and the random seed, which in view mode is the state root.

**One walk, many accounts.** A multisig sends the walk to its members, who may be contracts
on other shards, so a single bundle routinely spans several accounts, several contracts and
several shards. Grouping recorded nodes under the shard they came from keeps each set with
the root it hashes toward, which is how a verifier rebuilds them anyway: one partial trie per
shard.

Note that there is one entry per shard, not per contract. A shard's trie holds every account
on it, and every trie key embeds the account it belongs to, so two contracts on the same
shard read out of the same rebuilt trie without any chance of collision. A node picks the
entry to use by deriving the account's shard from the epoch's shard layout. Within a shard,
overlapping paths also cost nothing twice, since nodes are content-addressed.

Code is keyed by hash rather than by account, so a multisig whose three members run the same
wallet implementation carries that code once. Keying by hash is also what stops a bundle
misbinding code to an account: a node reads the account record, which is itself proved
against block B, takes the code hash named there, and looks that hash up, re-hashing the
bytes to confirm. The bundle has no say in which account runs which code, nor in where the
walk begins: the starting account and path come from the signed message, and everything
after them from `pending` results the node computed itself.

The provider always returns that code, since it has no way of knowing what any node already
holds. Trimming is the relay's job: it serves the bundle with code and without, and a node
takes the smaller form plus whatever hashes it lacks. Each shard visited adds one root proof,
which is a handful of hashes.

**The bundle covers a tree, not a list.** NEP-641 puts recursion on the caller's side:
contracts never call each other, and a resolver keeps calling `w_resolve_auth` on whatever
the last answer listed as `pending`. In this design that walk happens twice, for different
reasons.

The provider walks it to know what to record, since it cannot fetch the state for the second
layer until the first has run and named it. So it drives the loop locally, the way the
reference resolver drives it over RPC, and captures everything the whole walk touched,
including account and access-key state, because each step tries an access-key authorization
alongside the contract call. All of it at one block, as the standard requires.

Each MPC node then walks the same tree again during replay, following only the `pending`
results it computed for itself. That second walk is the one that decides. The provider's is
just a fetch strategy, which is why a provider that explores a different tree produces
nothing worse than a bundle missing entries the node needs.

The alternative is to leave tree logic out of the provider entirely and have the relay drive
the loop, calling the provider once per layer and concatenating what comes back. That works
and simplifies the endpoint, at the cost of a round trip per layer, and it is worth keeping
in mind as a smaller first version.

**The bundle must prove absence too.** The access-key attempt has two outcomes that are not
"here is the key": the account exists without the key, which is a rejection, or the account
does not exist, which still resolves when the account ID is the implicit one derived from
that public key. Both must be proved rather than asserted, or a provider omitting what it
did not find is indistinguishable from one hiding a key. Usefully this is close to free:
the recorder already walks and records the path to a key that is not there, so the
non-inclusion proof falls out of attempting the read, and the endpoint's job is to emit it
deliberately rather than drop it.

**How big is a bundle.** Proof material is small. A branch node is a tag byte, a two-byte
child bitmap and 32 bytes per present child, so 70 to 260 bytes; a path is ten to twenty
nodes; paths under one account share their upper half. An account record, its access key and
a few storage entries come to 5 to 15 KB per account, and absence proofs cost the same.

Contract code decides the rest. Measured from released NEAR artifacts: wNEAR 181 KB,
fungible-token 196 KB, non-fungible-token 303 KB, PoA factory 575 KB, defuse 1.2 MB, the MPC
contract 1.4 MB. The cap is `max_contract_size`, 4 MiB.

| Case                                 | Bundle        |
| ------------------------------------ | ------------- |
| Plain account, access-key leaf       | about 5 KB    |
| One wallet contract, code cached     | 10 to 15 KB   |
| One wallet contract, code not cached | 0.2 to 0.6 MB |
| 2-of-3 multisig, code cached         | 40 to 60 KB   |
| Same, code cold and distinct         | 1 to 2 MB     |

So the code-hash cache decides whether a bundle fits in a mesh message. For scale, a whole
chunk's state witness may reach `main_storage_proof_size_soft_limit`, 4 MB.

### Component 4: the relay to MPC message format

The object the relay puts on the wire. It is the network's ordinary signature request with
the material needed to authorize it bundled alongside, which is why it is named for that
rather than for the flow. It has to do three things: carry the user's signed message
untouched, name the block everything resolves at, and deliver the bundle. It travels
as an announcement with the bundle inline when small, or its hash when not, and logically
forms one object:

```
WitnessedSignatureRequest {
  nep641_message: OffchainMessage,   // spec-defined, signed by the user, frozen
  signatures: Vec<Signature>,        // spec-defined
  resolution_block_hash: CryptoHash, // unsigned: the block to resolve at
  witness_bundle: WitnessBundle,     // see Component 3
}
```

Each node computes `request_hash = SHA-256(WitnessedSignatureRequest bytes)` over what it
received, and that hash is bound into the signing session identity, so identical bytes at
every participant is enforced rather than assumed.

The block reference and witness need no user signature because they carry no authority. The
signed timestamp defines which blocks are acceptable; the unsigned block hash picks one, and
every node verifies the pick.

### Component 5: verifying the request (per node)

Verification runs against trusted block headers, so start there. A node needs recent _final_
headers for two things: the block timestamp, which is the chain clock, and
`inner_lite.prev_state_root`, one Merkle root over **every** shard's state root, computed as
`merklize(chunks.map(prev_state_root))` (`core/primitives/src/block.rs`). One header
therefore covers the whole chain, and a proof needs only the shard's state root plus its
path in that vector.

**Today: the embedded indexer.** Nodes already embed a nearcore node via `chain-gateway`
tracking one shard, and a node tracking one shard still fully validates every block header
for the whole chain; only chunk execution is limited. The header source therefore already
runs inside every node at no extra compute, disk or trust, and launch needs plumbing rather
than infrastructure.

**Later: an embedded light client**, delivering the same two primitives at a few megabytes
and under 0.1% of a core, from validator sets learned once per epoch. A future optimization,
not a launch dependency, since no maintained embeddable Rust light client exists.

Either way downstream sees the same interface, for final blocks only. Finality lands about
two blocks behind production, which rules out two honest nodes seeing competing chains.

With those in hand, "verify the request" means these six checks, run by every participant on the same
`WitnessedSignatureRequest` bytes before it contributes a share. They cover all three parts of it: the
signed message, the block it names, and the witness bundle.

Checks 1, 2, 3, 5 and 6 are deterministic functions of the request plus verified headers.
Check 4 deliberately is not, since it reads the node's own head. The asymmetry is safe in
one direction: integrity is deterministic, so no node can be pushed into accepting what
another correctly rejects, while liveness is not, so a lagging node can reject what its
peers accept and the request retries.

1. **Signature.** NEP-641/NEP-413 signature verifies for the claimed key.
2. **Block validity.** `resolution_block_hash` names a real, final block, verified against
   the node's own header view.
3. **Freshness floor.** At a contract step the verifying contract enforces this itself,
   panicking when the signed timestamp is later than the block's; at an access-key leaf it
   is ours. Running it up front turns a wasted tree walk into an immediate rejection.
   Compare against the right timestamp: the state committed in B came from an earlier chunk,
   so the check is `state_block.timestamp >= message.timestamp`, using that shard's chunk
   header height.
4. **Recency (our rule).** The block must be no older than the recency window measured
   against the node's own head, proposed at 60 seconds, and so must the shard's own chunk
   height. The standard recommends a recent final block but allows historical resolution,
   so without our rule an hour-old block would pass.
5. **TTL, if set.** `block.timestamp - message.timestamp <= TTL`. Contracts may impose their
   own; this one is the network's.
6. **Resolution.** The node walks the tree itself from the account and path in the _signed
   message_, every later call coming from `pending` results it has already verified, never
   from the bundle's contents or ordering. The bundle only answers storage reads, so a
   bundle describing a different tree does not redirect the walk, it just lacks entries and
   replay halts.

Any failure is a rejection, safe to retry with a fresher block. Every misbehaviour degrades
to "refuse".

**What an access-key leaf costs us.** At a contract step the contract checks itself and we
replay it. At a leaf every check is ours, and there are more than "the signature verifies":
the authorization must name the chain we are on, the account being resolved, and the ancestry
path we arrived by, so a leaf signed for one position in one tree cannot be lifted into
another. The signing time must not be later than the block's, and the key must still carry
full access, so a function-call key never suffices. Each is a way to diverge silently from
other resolvers, which argues for shared test vectors.

**How wide the block-shopping window is.** Checks 3 and 4 both apply, so an acceptable block
falls between the signing time and now, and no older than the recency window, so the room to
choose is whichever of those two is tighter: the age of the message, or the window. With the
standard's 60-second backdate and a 60-second window, a promptly submitted message lets the
assembler pick any block from the last minute, so an authorization revoked 30 seconds ago
can still resolve against a block from 45 seconds ago.

The recency window closes this, and the two bounds differ. TTL is measured from the message
timestamp, so a TTL below the backdate rejects honest messages, and the backdate is the
standard's guidance rather than ours. The recency window is measured from _now_, so setting
it to 10 seconds would cut the room to choose to 10 seconds even with a 60-second
backdate. What stops us is our own nodes: each checks against its own
head, a presignature's whole set must agree, and the node already tolerates peers 50 blocks
behind when deciding who is alive. Attacker freedom is bounded by how closely our slowest
participants track the chain.

### Component 6: local verified re-execution (per node)

Running the request's contracts on the node itself, over state that came from the bundle
rather than from local storage. Nodes already carry nearcore's runtime, since
`near-vm-runner` and `node-runtime` arrive through `near-indexer` and run every block for the
tracked shard, and `chain-gateway` already makes view calls through the embedded ViewClient.
What is new is where the state comes from: that path only works for a tracked shard.

It has to do three things: confirm the bundle's state is genuine, reproduce the resolution
exactly, and survive running code an attacker chose. The first two are a short sequence:

1. Checks every recorded entry and the code hash upward to the state root in the verified
   header. One flipped byte breaks the chain.
2. Re-executes, serving storage reads from the bundle (`Trie::from_recorded_storage` over
   the provider's `PartialState`). Anything omitted halts replay with "missing data", which
   means retry elsewhere, never an authorization answer.
3. Takes its _own_ result as the answer; the provider's claim is a debugging cross-check.

**"Deterministic" needs the context pinned.** `ViewApplyState`
(`runtime/runtime/src/state_viewer/mod.rs`) carries `block_height`, `prev_block_hash`,
`shard_id`, `epoch_id`, `epoch_height`, `block_timestamp` and `current_protocol_version`,
and the runtime sets `random_seed` to the state root for view calls. All of it is visible to
the contract, so provider and verifier must use identical values. All of it derives from
block B plus the shard id, so the request carries it explicitly.

Guardrails:

- **Gas cap, well below the default.** The request supplies the contract, so a hostile one
  is a given. `max_gas_burnt_view` unset falls back to `max_gas_burnt`, 1,000 TGas, and gas
  is calibrated at no more than 1 ms per TGas, so the default allows about a second of CPU
  per call, times the calls in the tree. Choosing a lower value is a requirement, not tuning,
  and bundle size needs a cap beside it.
- **Keep the attacker's code out of the enclave.** Nodes run in Intel TDX VMs holding key
  shares, and this design has them compile and run request-supplied WebAssembly on every
  request, where a runtime or JIT bug stops being a crash. Replay belongs in a separate
  sandboxed process with no key access, returning only the answer. Where that boundary sits
  is a prerequisite, not later hardening.
- **Cache code by hash, never by account.** The record proven at B names a code hash, and
  the node asks its cache for those bytes, not for "the code of this account". An upgrade
  changes that hash, so the lookup misses and the bundle supplies the new code: stale code is
  unreachable rather than guarded against. One wallet implementation across a thousand
  accounts is one cache entry.
- **Code can be global.** An `AccountContract` may be `Local(hash)`, `Global(hash)`, or
  `GlobalByAccount(account)`. The last is a pointer needing a second proven read at B, and
  the cache keys off the hash resolution lands on.
- **Match the storage mode.** `Trie::from_recorded_storage` takes a `flat_storage_used`
  flag, and flat-storage reads record differently from trie reads, so disagreement fails
  replay on valid requests.
- **Bound the tree, not just each call.** Sub-authorizations come from attacker-controlled
  output and the standard permits terminating cycles, so caps on depth and count are the only
  guarantee the walk ends. Identical everywhere, or nodes disagree because one gave up first.
- **Select the protocol version, do not just track it.** The rule is "run what the chain used
  at block B", and nearcore is built for it:
  `runtime_config_store.get_config(protocol_version)`. Older blocks then replay correctly
  across upgrades. The tax is the binary: a new protocol version needs a release that knows
  it, and `assert_supported_protocol_version` refuses anything outside the built range, so
  nodes must upgrade before activation.

### Component 7: leader election and signing

How one verified request becomes one signature. It has to settle two things without
coordination: who drives the attempt, and which nodes sign. The second is not ours to choose,
because each stored presignature records the participant set that produced it
(`PresignOutputWithParticipants`, `crates/node/src/providers/ecdsa_common.rs`) and the store
drops one as soon as any of them goes offline, so the set is a precondition rather than a
label.

**Today.** A request arrives through the indexer as an on-chain `sign()` call. Every node
sorts participants by `SHA256(participant_id || request_id)` and takes the first eligible
one as leader (`crates/node/src/requests/queue.rs`), so all nodes agree without talking. A
node that is not the leader then does nothing at all; the work is gated on
`leader == my_participant_id`. The leader takes one of its own presignatures (`take_owned`)
and opens a channel to that presignature's participants, and only then does each follower
look the request up **in its own store**, refusing to proceed if it is absent
(`crates/node/src/providers/ecdsa/sign.rs`). So agreement is not a vote, it is every
prompted participant having independently seen the same on-chain request.

**Two gaps for our path:**

- **A trigger and a leader without an indexed block.** Nodes feed requests into the same
  `sign_request_store` from the broadcast, and leadership stays a deterministic function of
  the request hash over the alive participants, so the broadcast does for us what the indexer
  does for `sign()`.
- **When to verify.** Keeping the prompted model matters more here than on chain, because our
  verification is expensive: a bundle fetch and a full tree replay, versus reading a request
  the indexer already delivered. Verifying eagerly on every node would burn that on nodes
  that never sign. So follow the existing shape, verify when prompted, and at most prefetch
  the bundle, which is cheap and cacheable, while deferring replay until the leader asks.
- **Failing fast, so rejections cost a moment rather than a minute.** Taking a presignature
  removes it from storage, and today a follower that lacks the request waits in
  `sign_request_store.get` until the signature timeout, currently 60 seconds, before the
  attempt collapses. Four changes fix that, in increasing order of effort.

  First, distinguish "not yet" from "no". A follower still waiting for the broadcast should
  wait, but one that holds the request and rejects it should return an error, which the
  existing `MpcLeaderCentricComputation` already turns into an immediate Abort to the leader.
  No new message type is needed.

  Second, have the leader verify before it takes a presignature. Checks 1, 2, 3, 5 and 6 are
  deterministic in the request bytes, so anything that survives the leader's own pipeline can
  only fail at a follower on check 4.

  Third, pick a set that will pass check 4. Participants already publish indexer heights
  through `IndexerHeightTracker`, so the leader can prefer a presignature whose participants
  are fresh enough for block B instead of discovering the problem by rejection.

  Fourth, return the presignature when nothing was revealed. A presignature is dangerous only
  if used for two different messages, so an attempt aborted before any share is sent has not
  spent it. That is the phase-1 vote's benefit without a separate round, and it needs the
  signing side to confirm exactly when a share counts as revealed.

Liveness follows the unanimity math: if each participant rejects independently with
probability p, an attempt succeeds with probability (1 − p)^s for a set of size s, and the
leader's retry loop covers the rest. Usefully, `all_alive_participant_ids`
(`crates/node/src/network.rs`) already drops participants trailing by more than
`MAX_INDEXER_HEIGHT_DIFF`, 50 blocks or roughly a minute, and presignatures are pruned by
the same signal, so the recency window should agree with that tolerance.

**Two ways the pool drains faster than it looks.** The buffer is small, with the sample
config asking for `desired_presignatures_to_buffer: 64` and replenishment costing triple
generation. And leader election tolerates disagreement by design: the queue's own docs note
that differing connectivity or indexer heights can give a request more than one leader. On
chain that is harmless, since the contract takes the first response; off chain each extra
leader spends its own presignature. So rank leaders deterministically by `request_hash` with
backoff for lower ranks, and have a leader confirm the announcement propagated before taking
a presignature.

A malicious participant can still accept and then stall. The mitigation is bookkeeping:
track aborts per participant, bias selection away from repeat offenders, and size
replenishment for off-chain load on top of `sign()` traffic.

---

## Why does the request carry a block at all?

Every node has to resolve against the same state, or they reach different answers and no
signature forms. The chain gives no such agreement for free once the request stops being a
transaction, so something has to name a block, and whatever names it becomes a place where a
hostile party might steer the outcome.

**Option A: the relay carries it, discovered from the fetch (recommended).** The provider
resolves at its latest final block and reports which, and the relay passes that along with
the bundle. Nodes verify rather than negotiate: any block passing checks 2 through 5 is
acceptable by construction, so the proposer's motives do not matter. No coordination rounds,
one bundle serves everyone, and a lagging node triggers a retry rather than a split decision.

**Option B: the session leader picks it.** The leader fetches the bundle and includes both in
the session initiation. Structurally this _is_ Option A with the leader as requester, reusing
the pipeline unchanged, except that block picking and witness fetching move inside the nodes,
which then need their own provider connections and retry loop.

**Option C: a periodic checkpoint beacon.** Every T seconds the nodes agree on a checkpoint
block and requests arriving in the interval resolve there. This amortizes agreement across
requests but imports consensus machinery: beacon liveness becomes a hard dependency of all
authorization, checkpoint lag adds T seconds on top of the recency window, and a message
signed after the
current checkpoint waits for the next one.

**We choose A.** The old argument for B was ecosystem friction, which owning the relay
dissolves, since clients never see blocks either way. That leaves the question of where the
block-picker lives: in a stateless service we already run, or inside the signing protocol
with extra outbound dependencies. B stays the fallback if MPC input ever needs to be
independent of any relay, and since it reuses every component, building A first costs
nothing. Avoid C unless a strong reason appears.

---

## How does a request get from the relay into the MPC network?

The relay has the request and every node needs it, but nodes are TEE machines that should
not grow a public inbound surface, and the network is meant to keep growing without the relay
changing shape.

**Option A: through the MPC contract**, the way `sign()` works today. Rejected: it puts an
on-chain transaction, its gas cost and seconds of latency inside a flow whose entire purpose
is to stay off chain.

**Option B: a star**, every node holding a stream to the relay. Rejected: connections, TLS
identity management and relay egress all scale linearly with network size, and it ignores the
dissemination network the nodes already run.

**We choose C: inject through a few entry nodes and let the mesh spread it.** No transaction
anywhere in the request path. The relay pushes to k rotating entry nodes, the announcement
travels the mesh the nodes already maintain for signing, and bundles too large to travel
inline are pulled content-addressed from a cacheable endpoint. That splits into a control
plane and a data plane:

- **Control plane: announcements over the existing mesh.** The relay connects only to k
  entry nodes, chosen by deterministic rotation, and they _dial out_ (mutual TLS). Nodes are
  not otherwise unreachable, since participants publish a `url` and `tls_public_key` on
  chain and accept each other's connections. What this design adds is no inbound surface
  reachable from outside the participant set. Announcements carry the signed message, block
  B hash, and the bundle inline or its hash, plus the relay's signature, deduplicated by
  `request_hash`.
- **Data plane: large bundles pulled by hash.** Anything above the inline threshold is
  fetched with `GET /bundle/<bundle_hash>` and checked against it. Content-addressing makes
  that trivially cacheable, with a CDN in front and providers or replicas as mirrors, so
  origin bandwidth stays flat.

**Why fetch rather than push.** Not a size limit: `MAX_MESSAGE_SIZE_BYTES` is 100 MB
(`crates/node/src/network/constants.rs`), so even a maximal bundle passes inline. It is where
the cost lands. The mesh is a full mesh of direct connections and a broadcast is a loop
sending the same bytes to each participant, so pushing makes the sending entry node upload
the bundle once per node: over 100 MB of egress from one TEE machine for a 4 MB bundle across
30 participants, on a link shared with the signing protocol.

Two refinements. Bundles under about 64 KB should ride inside the announcement, which covers
every warm-cache case including a small multisig and saves a pointless round trip. And if the
relay becomes unreachable after the announcement spreads, every node holds a hash and no
bytes until timeout, so nodes should serve bundles to each other by hash.

Scaling: relay connections O(k) regardless of network size; announcements ride a mesh that
must scale for signing anyway; bundle distribution is CDN-shaped. Growing the network needs
no relay-side change.

Implementation:

1. **Node: entry-node duty plus a broadcast message type.** A new mesh message type carries
   announcements, nodes in a rotation slot dial the configured relays and forward
   announcements inward, and every node feeds verified requests into the existing
   signing-session machinery. This second, off-chain trigger beside the indexer-event trigger
   is the main structural change in node code.
2. **Equivocation control.** `request_hash` is part of the session identity, so anyone
   spreading different bytes to different nodes cannot split the decision, only fail to
   assemble a threshold behind any one hash. Integrity never depends on the transport
   behaving; only liveness does.
3. **Bundle delivery.** Fetch by hash from CDN, mirror or origin. The relay serves each
   bundle in two forms, with contract code and without, since only a node knows what its own
   cache holds. A node takes the code-less form and fetches any code it lacks by hash, which
   is also why code caches well: the same wallet implementation is one hash across every
   account using it.
4. **Response: the leader posts it.** Entry nodes exist because the relay cannot dial nodes,
   so pushes need held streams. The return path needs none, since every node already calls
   the relay outbound. The leader sends the signature to `POST /result/<request_hash>` on the
   instance the announcement named, removing a hop and taking entry nodes out of the response
   path. Session timeouts plus a relay retry with a fresh block B handle whatever never
   reaches threshold.

That endpoint is the one place the relay holds state: a map from request hash to the waiting
client connection, ephemeral and expired by the session timeout. Nothing durable to
replicate. Authentication on it is covered below.

Latency: no on-chain hop. This transport adds one mesh broadcast and one cacheable fetch per
node, both of which should be small next to the signing session, though that ordering is an
expectation to confirm against `near_mpc_signature_time_elapsed`.

### What stops an entry node from quietly dropping requests?

Concentrating the relay's reach into k nodes hands those k a chokepoint, and they rotate, so
the chokepoint moves. The reassuring half is that an entry node can never change what the
network signs, since every node verifies the request and `request_hash` binds the session, so
the whole attack surface is delay and withholding. Three rules shrink it:

- **The relay signs every announcement**, with an expiry, so an entry node cannot fabricate,
  replay or amplify, only drop.
- **The relay pushes to every live connection**, so withholding takes every current entry
  node colluding at once rather than one defecting.
- **k live connections, not k assigned slots.** Rotation produces an ordered candidate list
  and the relay holds connections to the first k that are up, so a node going down becomes a
  reconnect rather than a hole lasting until the next rotation.

What remains is the correlated case, since selection is per window. If a third of nodes are
hostile and k = 3, roughly one window in 27 draws an all-hostile entry set, and in that
window _every_ request stalls rather than 3.7% of them. Those requests are not lost, they
time out and the relay retries, so the cost is latency for one window. Raising k or
shortening the window buys that down, and if withholding ever shows up in practice, numbered
announcements with fetch-by-number would make it detectable rather than merely survivable.

Rotation is deterministic, unpredictable, and needs no new agreement:

- Each node sorts participants by `H(seed || participant_id)` and takes the top m ≈ 2k, the
  first k as primaries and the rest as hot spares.
- The seed is the hash of the first final block in the window, which every node already
  verifies, so nobody can steer the draw.
- The relay accepts any node in the top m and pushes to all of them, absorbing disagreement
  about window boundaries.
- Slots are staggered, each with an overlap window: dial slightly early, hold slightly late.
- A node may decline the duty and the next spare takes it.

Rotation lives entirely on the node side. The relay computes no schedule, accepting whoever
presents a valid participant identity up to a connection cap, so a rotation change ships with
a node release. The period is open: minutes rather than hours, and its own concept rather
than the key-resharing epoch.

### How do nodes and the relay authenticate each other?

Three endpoints face the nodes, and the tempting answer, authenticate everything, is wrong on
one of them. Authentication is doing a different job in each case, so each gets a different
answer.

**The announcement stream (entry node dials the relay): mutual TLS, both directions
grounded on chain.** The node checks the relay's presented key against the voted
`identity_key`, which is what stops a hijacked address impersonating a relay. The relay
checks the node against `ParticipantInfo.tls_public_key`, the same credential nodes already
use with each other, so no new key material or distribution is needed. Neither check is an
integrity input, since a rogue relay cannot forge a request and a rogue node cannot forge a
signature; both exist to keep strangers from consuming resources.

**`GET /bundle/<bundle_hash>`: deliberately unauthenticated.** The content is self-verifying, so
authentication buys no integrity, and adding it would break the CDN caching the design
depends on. Abuse is a bandwidth problem, answered with rate limits and cache rules rather
than credentials.

**`POST /result/<request_hash>`: authenticated for spam only.** Correctness does not need it,
since the relay verifies the threshold signature against the network's public key before
answering the client. But an open endpoint invites junk that costs a signature verification
each, so the poster presents its participant certificate over the same mutual TLS as the
announcement stream. A leader posting a result is already dialling out, so this reuses the
credential rather than adding one.

Worth deciding rather than inheriting: an unauthenticated bundle endpoint means anyone
holding the hash can read what the authorization touched, and a CDN in front sees it too.
Hashes only travel to participants, so this is not open to the world, but bundles are not
secret either. If off-chain requests are meant to be private, that conflicts with
CDN-cacheable bundles and the resolution belongs with the audit-trail question below.

### How does a node know which relay to listen to?

Witness providers could stay in local config because their output is verified (Component 1).
Relays cannot: a node that accepts requests from a relay nobody sanctioned lets a stranger
consume network resources, and nodes have to agree on who may inject at all. So this list
comes from somewhere the whole network shares. Configuration flows both ways here, but only
one direction has to be trusted.

**Nodes read the relay set from the MPC contract**, through the shard they already track, so
there is no seed file, no DNS to trust, and no chicken-and-egg at startup. The contract
already does this for foreign chains: `vote_update_foreign_chain_providers` maintains a voted
whitelist of `ProviderConfig { base_url, auth_scheme, chain_routing }` entries, and
participants are stored as `ParticipantInfo { url, tls_public_key }`.

**The relay reads almost nothing** from the chain, and only one of those reads matters. The
latest final block comes from ordinary untrusted RPC, since getting it wrong just bounces a
request off check 4. The MPC network's public key (`public_key(domain_id)` on the contract)
is different: the relay verifies posted signatures against it, so a hostile RPC serving the
wrong key would let an attacker post a forgery the relay then hands to the client. Client-side
verification catches that, but the relay should not be the weak link, and the key changes
only at key events, so pin it in relay config and refresh deliberately. Reading the
participant set for admission and metering is optional. The relay never needs to know which
node produced a signature, only that it verifies.

**Vote on identity, never on location.** What goes on chain is a long-lived key and a stable
name:

```
relays: [
  { id: "near-one-relay",
    identity_key: ed25519:...,
    name: "relay.mpc.near-one.org" },
]
```

Addresses behind that name change as often as operations demands without touching the chain.
The TLS handshake proves the node reached the right relay, since it checks the presented key
against the voted `identity_key`, so hijacked DNS yields a connection that fails the check.
This also drops the certificate-authority dependency.

**Routine key rotation happens below governance.** The identity key signs short-lived records
certifying instance keys and endpoints, so operators rotate keys and add replicas freely. A
vote is needed only to admit an operator, remove one, or replace a compromised root key.

**The list is an allowlist, not a trust root.** A relay cannot forge state or make any node
sign anything, so a wrong list costs availability, never correctness. The update path need not
be fast or atomic, and each operator should be able to locally refuse a relay immediately,
with the vote formalizing it later.

**Replication.** Instances share one relay identity. One instance holds the client's request,
so the announcement names which, and the leader posts the result there. Entry nodes hold one
stream per listed instance, giving k × R connections, still independent of network size and
needing no shared state. A shared bus is the fallback.

**Two relays injecting the same message** pick different blocks and bundles, so the requests
hash differently and burn two presignatures for one client request. Deduplicating a level up,
on the signed-message hash, would prevent that, but it needs state nodes do not keep today: a
short-lived map from message hash to "in flight" or "answered, here is the signature", held
by whoever owns it. Note that only the original participants hold a finished signature, so a
cached answer has to come from one of them. Re-delivery is safe where resolving afresh would
not be, since the signature already exists and a second copy grants no new authority.

Two consequences to accept, both to settle with the MPC and contract teams:

- **Payment and metering move off-chain.** No deposit in the path means per-request payment
  cannot come from attached NEAR, so the relay becomes the metering point.
- **No automatic on-chain audit trail.** `sign()` requests are public by construction; these
  are not. Logging request hashes or periodically anchoring a Merkle root is cheap. Decide
  deliberately rather than losing the property by accident.

---

## Security analysis

| Threat                                                            | Defense                                                                                                                                              |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Forged state or code from a provider                              | The Merkle chain must land on a state root in a validator-signed final header.                                                                       |
| Omitted state entries                                             | Replay halts on missing data; retry elsewhere. Fail-closed.                                                                                          |
| Provider hides an existing key by reporting absence               | Non-inclusion proofs, so "not found" is proved rather than asserted.                                                                                 |
| Resolution against pre-revocation state                           | Freshness floor (check 3), enforced by verifying contracts and by us at access-key leaves.                                                           |
| Old-but-post-signing block where a just-revoked auth still passes | The recency check and TTL. What remains is whichever is tighter, the message's age or the recency window.                                            |
| Hostile contract burning node CPU                                 | `max_gas_burnt_view` set well below the 1,000 TGas default, plus a bundle size cap.                                                                  |
| Hostile contract attacking the runtime inside a key-holding TEE   | Replay in a sandboxed process with no key access. A prerequisite, not later hardening.                                                               |
| Unbounded tree fan-out from attacker-controlled `pending`         | Network-wide caps on depth and sub-authorization count, identical on every node.                                                                     |
| Duplicate leaders draining the presignature pool                  | Deterministic leader ranking with backoff, and no presignature taken before the announcement propagates. Buffer is 64 by default.                    |
| Lagging or lying header source, chain forks                       | Headers fully validated by the embedded node, final blocks only, so a stale source causes rejections, not wrong answers.                             |
| Stalled shard: block time fresh, shard state minutes old          | Checks 3 and 4 use the shard's own chunk height, not only block time.                                                                                |
| Provider replays under a different epoch or protocol version      | Execution context pinned field by field and checked against B.                                                                                       |
| Protocol upgrade splits chain and embedded runtimes               | Config selected by B's protocol version; a newer version is refused outright, so nodes upgrade ahead of activation.                                  |
| Witness provider unavailability                                   | Multiple independent providers with failover; the provider is stateless and replaceable.                                                             |
| Provider lagging behind the chain                                 | B fails check 4 against each node's own head and the relay retries. A wasted round trip, never a stale authorization.                                |
| Compromised relay                                                 | Every field is verified by every node, so it can censor, delay, or pick any block inside the allowed window, never forge state.                      |
| Relay or entry-node equivocation                                  | `request_hash` binds the session identity, so mismatched bytes cannot form a session; equivocation causes a timeout.                                 |
| Entry node withholding                                            | The relay pushes to every live connection, so all of them must collude, and rotation replaces dead entries. A stalled request times out and retries. |
| Entry node forging, replaying or amplifying                       | Announcements are signed by the relay's voted identity key and carry an expiry.                                                                      |
| Relay impersonation by DNS or routing hijack                      | Nodes pin the identity key from contract config and check it in the TLS handshake.                                                                   |
| Same message injected through two relays                          | Dedup on the signed-message hash, so one client request cannot burn two presignatures.                                                               |
| Relay fooled about the participant set                            | Only gates admission and metering; integrity never depends on it.                                                                                    |
| Participant accepts then stalls, burning a presignature           | Bookkeeping: track aborts, bias selection away from offenders, replenish in the background.                                                          |

Replay of a whole request is out of scope: NEP-641's nonce semantics and the target
contract's own replay handling govern it.

---

## What exists today vs what we need built

### Exists today (checked against `nearcore` at 2026-08-17, `mpc` at 2026-08-14, `intents` at 2026-08-13)

- **A reference resolver with this design's shape.** `RpcResolver`
  (`crates/signatures/nep641/src/resolver/` in `near/intents`). Recursion is caller-side: one
  loop calls the view method, reads `pending`, and pushes the next calls onto a pool of
  in-flight futures. No promises, no contract-to-contract hops. Each step attempts the
  access-key authorization and the contract call in parallel and prefers the access key, and a
  mismatch between a parent's `expect` and the child's result aborts the whole resolution. It
  pins one block for the entire tree, and exposes an override to resolve everything at a
  block the caller names, which is what an MPC node needs when it replays against the block
  the request carries.
- **Storage recording and partial-trie replay.** `Trie::recording_reads_*` and
  `Trie::from_recorded_storage` over a `PartialState` (`core/store/src/trie/mod.rs`), the
  NEP-509 machinery, reused for one view call instead of a chunk.
- **A view-call entry point with the pieces we need.** `TrieViewer::call_function`
  (`runtime/runtime/src/state_viewer/mod.rs`) takes an explicit `ViewApplyState`, selects
  runtime config by protocol version, and caps execution. What it does not do is record
  storage or package proofs, which is the gap the new endpoint fills.
- **State roots for every shard in one header field.** `inner_lite.prev_state_root`
  (`core/primitives/src/block.rs`), also part of the light-client payload.
- **Light-client protocol and serving endpoints.** `next_light_client_block` and
  `chain/chain/src/lightclient.rs`.
- **Embeddable contract runtime.** `near-vm-runner`, already in the node through
  `near-indexer`, though with no stability guarantee for external embedders.
- **Liveness filtering in the node.** `all_alive_participant_ids`
  (`crates/node/src/network.rs`) excludes participants trailing by more than
  `MAX_INDEXER_HEIGHT_DIFF`, and presignature storage prunes sets no longer alive.
- **Voted provider whitelists in the contract.** `vote_update_foreign_chain_providers` is the
  shape a relay list should follow.

### Needs building, by team

| Deliverable                                                                                                                                                                                | Owner (proposed)               | Notes                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `witness_view_call`: view call with recording on, proofs to `inner_lite.prev_state_root`, non-inclusion proofs for missing accounts and keys, pinned execution context, tree-wide bundles  | us, or the nearcore team       | The one genuinely new piece outside the MPC network. Primitives exist; the packaging does not. Absence proofs are least likely to fall out of the recorder for free. |
| Supported-embedder story for the crates we depend on: semver expectations, upgrade notice period, protocol config feed                                                                     | nearcore team                  | `node-runtime`, `near-store` and `near-epoch-manager` are `publish = false`, so we track internals by git tag and chase them at every bump.                          |
| Production-grade Rust light-client library                                                                                                                                                 | us / ecosystem, later          | Not launch-blocking, since the embedded indexer already validates all headers.                                                                                       |
| Relay service: accept signed messages, pick a final block, fetch the bundle, inject `WitnessedSignatureRequest`, serve bundles, accept posted results                                      | us                             | Clients need standard NEP-641 signing plus one HTTP call.                                                                                                            |
| Node: mesh announcement type, entry-node rotation and outbound relay client, bundle fetcher with code-hash cache, request-hash session binding, signed-message dedup cache, result posting | us                             | The structural change: a second, off-chain trigger for signing sessions beside the indexer-event trigger.                                                            |
| MPC contract: config entries for relay identities (key plus stable name)                                                                                                                   | contract team (us)             | Config only. Addresses stay off chain, so operational churn never needs a vote.                                                                                      |
| Off-chain payment and metering model                                                                                                                                                       | us + MPC operators             | No deposit in the path; the relay is the metering point.                                                                                                             |
| MPC node: verified headers exposed via `chain-gateway`, the pipeline, sandboxed replay, policy knobs (recency window, TTL, tree caps, gas cap)                                             | us                             | The bulk of our own work.                                                                                                                                            |
| Independent witness provider deployments                                                                                                                                                   | MPC operators / infra partners | At least two before mainnet.                                                                                                                                         |

### Client guidance

Backdate signing timestamps by about 60 seconds, per the standard, so honest messages are not
rejected as future-dated against a block a few seconds behind wall clocks.

---

## Building `witness_view_call`

The endpoint does not exist, so this is the piece most likely to be waved through in review
and then discovered to be someone else's roadmap. It is not: the primitives are all public
functions in nearcore, and a provider can be our own binary. What we need from the nearcore
team is a decision about ownership and stability, not permission.

**The primitives exist.** `TrieViewer::call_function` and `TrieViewer::new` in `node-runtime`
run a view call with an explicit context. `Trie::recording_reads_*` turns recording on,
`Trie::recorded_storage` extracts what was read, and `Trie::from_recorded_storage` rebuilds a
trie from it on the verifying side, all in `near-store`. Non-inclusion proofs largely come
free, since the recorder already walks and records the path to a key that is not there.

**It cannot be a sidecar.** nearcore's store has no secondary-instance mode and its
`ReadOnly` mode is for offline tooling, so a second process cannot follow a live node's
database. A provider owns its node.

**The work is glue plus one contract.** Wiring the pieces is a few hundred lines: resolve the
account to its shard using the epoch's layout, take the state root from B's chunk header,
supply an `EpochInfoProvider`, run with recording on, and package proofs up to
`inner_lite.prev_state_root`. The harder half is the agreement between provider and verifier,
which must pin the execution context, the storage mode (flat-storage reads record differently
from trie reads), and the state-root convention. Disagreement there shows up as "missing
data" on perfectly valid requests, so it wants shared test vectors and differential testing
against real contracts, not prose.

**The exposure is stability, not access.** `node-runtime`, `near-store` and
`near-epoch-manager` are `publish = false`, so they come by git tag rather than crates.io,
exactly as the MPC node already consumes nearcore. That is nearcore calling them internal
with no compatibility contract, so every version bump can move them under us. The same
applies to the replay path inside the node (Component 6), which is why the supported-embedder
question matters more than it looks.

**One thing the recorder cannot capture.** Contracts may call `validator_stake` and
`validator_total_stake`, which report how much a validator has staked. Those numbers come
from the epoch's validator set rather than the shard's key-value state, so no amount of
recorded storage covers them. A replaying node reads them from its own embedded nearcore
node, which tracks validator sets for the whole chain whichever shard it follows, and only
needs to know which epoch to look in, which is one reason the execution context names it.
Dropping the indexer for a light client later would mean that light client supplying the same
data.

---

## Open questions

1. **The recency window.** 60 seconds proposed, and it should not be materially tighter than
   `MAX_INDEXER_HEIGHT_DIFF`. Needs measurement against real head lag.
2. **TTL policy.** Does the network impose its own on top of per-contract TTLs, and at what
   value?
3. **Witness bundle limits.** Maximum recorded entries, code size and gas, which bound how
   expressive extension contracts may be.
4. **Protocol upgrade operations.** How nodes learn of and roll out version bumps without an
   authorization outage.
5. **Tree caps: the numbers, not the knobs.** The reference exposes two, total
   sub-authorization count and maximum depth, refusing a depth larger than the count, and both
   default to zero. Ours must be network policy, not per-node config.
6. **Transport mechanics.** k and m, rotation period and stagger, stream protocol, session
   timeouts, CDN topology.
7. **Code cache policy (follow-up, after this design is accepted).** Warm-up and eviction,
   which the sizing makes load-bearing: a hit keeps a bundle at tens of KB, a miss pushes it
   past half a megabyte.
8. **Payment and audit trail.** How operators are paid with no deposit in the path, and
   whether to anchor a periodic Merkle root of served requests on chain.
9. **Block-picker placement.** Whether the block keeps arriving with the request or is chosen
   by the session leader instead.
10. **Presignature pool policy.** Replenishment against expected load, selection policy, and
    whether off-chain requests share the pool with `sign()` traffic.
11. **How tight can the recency window go?** Its floor is head lag across a presignature set,
    not anything in the standard, so measuring that tells us what each second of it buys.
12. **Accounts that do not exist yet.** The resolver accepts an access key for an account with
    no state when the account ID is the implicit one derived from that key, and it carries a
    disabled path for resolving contract authorizations against a deterministic account's
    initial state, pending RPC support. So some accounts are addressable, fundable and
    authorization-relevant with nothing in the trie. We need a position: non-inclusion proofs
    are assumed by Component 3, and contract resolution against a not-yet-deployed wallet is
    either in scope at launch or explicitly refused.
13. **How far to take fail-fast.** Explicit rejects and leader-side pre-verification are
    cheap. Returning an unspent presignature to the pool needs the signing side to define
    when a share counts as revealed.
14. **Relay set governance.** Threshold, time to take effect, whether the list wants a size
    cap, whether per-operator deny lists are policy or code, and how long a signed endpoint
    record lives.
15. **Where replay is sandboxed.** Separate process, separate VM, or stronger, and what it
    costs per request.
16. **Is the total cost still worth it against the on-chain path?** That route was rejected
    early for latency and gas, and this one has since accumulated a nearcore endpoint, an
    embedded runtime with an upgrade obligation, a sandbox boundary, a transport layer and a
    governance surface. The latency argument still holds, but the comparison deserves
    restating with the real cost of each side.
17. **Client API details.** How long the initial wait should be, the error taxonomy, whether
    rejection hints are exposed verbatim or normalized, and how many retries the relay makes
    before giving up.
18. **Message-level deduplication.** Where the cache lives, how long entries survive, and how
    it interacts with NEP-641's own nonce and replay semantics.
