# Signed Negative and Inconclusive Outcomes for Foreign Transaction Verification

**Status:** Draft for discussion · **Author:** Haiyue Chen (with Claude) · **Date:** 28 September 2026

## Summary

Today a foreign transaction request is signed only when the transaction checks out. Anything
else times out after the 200 block yield window, so a caller can't tell a failed transaction
from an MPC outage.

With this design, a V2 request gets one of three signed answers:

- **Success**, as today.
- **Negative verdict:** the transaction failed or was not found, the log index is out of
  range, the account was not found, the block is not canonical, or the values differ from
  the ones the caller expects. Signed under the same rules as a success.
- **Inconclusive:** the nodes disagreed, or transient errors kept too many nodes from reaching a
  verdict. It says nothing about the transaction.

If the network can't sign at all, the request still times out.

In short:

- Callers opt in through a new method, `verify_foreign_transaction_v2`. V1 is unchanged.
- Every V2 answer is tied to the one request it answers, so an old _not found_ can never
  answer a newer one.
- Every V2 answer also records the block the request was made in, and nodes only sign within
  200 blocks of it. Anyone who receives the signature later, even outside NEAR, can tell when
  the network checked.
- The caller states the values it expects. Nodes check them, so a success means the values
  the caller asked for.
- V2 collects outcomes before it signs. Every node inspects once, signs what it found with a
  dedicated Ed25519 key, and sends it to the other nodes. The leader signs a verdict as soon as
  t nodes signed the same one, with an asset among those nodes. Inspections are never retried.
- Only an acting leader (see "Deciding and signing") can get the network to sign, and only
  with signed node outcomes as evidence.

## Vocabulary

The doc uses these terms for the levels of an answer, from the bottom up.

| Term | Who | Meaning |
|---|---|---|
| Verdict | One inspector, so one provider | What one provider says about the transaction: found, with the extracted values, or a negative verdict such as not found. |
| Node outcome | One node | What one node concludes from its verdicts, after retrying transient errors: a verdict all its answering inspectors agree on, checked against the caller's expected values, or no verdict, because of transient errors or because its inspectors disagree. Every node signs its node outcome once per request and sends it to the other nodes. |
| Decision | An acting leader | What the leader does with the node outcomes: sign a verdict once t nodes signed it, sign an inconclusive once no verdict can reach t, and wait in every other case. |
| Signed outcome | The network | The answer the caller gets: success, negative verdict, or inconclusive. |

---

## Architecture

Callers talk to the contract as they do today. What changes is what the nodes sign, and how
they agree on it.

![Overview: the caller makes V2 requests with expected values to the MPC contract, which returns the signed outcome. All MPC nodes observe requests and send each other their signed node outcomes. The leader decides from those outcomes, coordinates the signing rounds with the followers, and sends responses to the contract.](attachments/overview.png)

1. **Request.** The caller calls `verify_foreign_transaction_v2` with the values it expects.
   The contract picks a yield id, stores the request, the hash of the expected values and the
   current block height under it, and announces the id in an event. Every node's indexer picks
   up the request and the id together.
2. **Inspect.** Every node that supports the chain inspects the request once. It signs its node
   outcome with its outcome key and sends it to every other participant.
3. **Decide.** An acting leader counts the signed outcomes. Once t nodes signed the same
   verdict, it signs that verdict. Once no verdict can reach t, it signs an inconclusive.
   Until then it waits for more outcomes.
4. **Sign.** The leader picks an asset among the nodes that back the outcome and sends Start
   with the outcome and its evidence. Each signer checks the request, the leader and the
   evidence, then sends its share.
5. **Respond.** The leader submits the yield id, the outcome and the signature. The contract
   looks up the request, rebuilds the hash, checks the signature and resumes that yield.

### Payload and response types

```rust
struct BlockHeight(u64);                           // a NEAR block height
struct YieldId([u8; 32]);                          // picked by the contract, see "Yields and the respond method"

enum ForeignTxSignPayload {
    V1(ForeignTxSignPayloadV1),                    // unchanged
    V2(ForeignTxSignPayloadV2),
}

struct ForeignTxSignPayloadV2 {
    request: ForeignChainRpcRequest,
    expected_values_hash: Hash256,                 // sha256 of the Borsh encoded expected values
    request_block_height: BlockHeight,             // the block the request's yield was created in
    yield_id: YieldId,                             // the one yield this answers
    outcome: ForeignTxVerificationOutcome,
}

enum ForeignTxVerificationOutcome {
    Verified {},                                   // the values match the expected ones
    Negative { verdict: ForeignTxVerificationNegativeVerdict },
    Inconclusive {},
}

enum ForeignTxVerificationNegativeVerdict {
    TransactionFailed,
    LogIndexOutOfBounds,
    TransactionNotFound,
    AccountNotFound,
    NonCanonicalBlock,
    ValuesMismatch,                                // found, but the values differ from the expected ones
}
```

- **Negative verdicts carry no extra data.** The inspector's `NonCanonicalBlock` also reports a
  height and two block hashes, but those come from whichever provider answered and differ
  between nodes during a reorg. Every node must sign the same bytes, so we leave them out of
  the payload. The node logs them, so failures can still be debugged.
- **Provider errors never become verdicts.** A node retries transient provider errors within
  its 5 second inspection cap. If its inspectors still give no verdict, or they disagree, it
  reports no verdict with the reason. A node never picks between its inspectors (see
  [Calculating supported foreign chains](../calculating-supported-foreign-chains.md)).
- **The inconclusive outcome is not a verdict.** A verdict is a fact about the foreign chain.
  It says nothing about the transaction, so it has its own variant instead of being one of the
  negative verdicts.
- **A success means the values the caller expects.** Each node compares the values it
  extracts with the request's expected values, and a difference is the negative verdict
  `ValuesMismatch`. The payload carries the hash of the expected values, so a success carries
  no values of its own.

```rust
struct VerifyForeignTransactionRequestV2 {
    request: ForeignChainRpcRequest,
    domain_id: DomainId,
    expected_values: Vec<ExtractedValue>,          // one per extractor, in extractor order
}

struct VerifyForeignTransactionResponseV2 {
    payload_hash: Hash256,
    signature: SignatureResponse,
    request_block_height: BlockHeight,
    yield_id: YieldId,
    outcome: ForeignTxVerificationOutcome,
}
```

- **The contract stores a hash of the expected values.** The values have no size cap, so the
  contract hashes them when the request arrives and keeps only the 32 byte hash. Nodes read
  the values from the request's receipt.
- **No expected payload hash.** V1 has one for replay protection. In V2 the yield id gives that
  protection, and a caller couldn't compute the payload hash in advance anyway, because it
  includes the yield id.
- **A receiver outside NEAR checks the signature.** It knows the values, computes the hash,
  rebuilds `ForeignTxSignPayload::V2` and verifies the signature. The SDK's signature verifier
  does this for V1 today. We extend it to V2, and document the steps for callers who don't use
  it.

### Yields and the respond method

**Yield ids.** The contract keeps a `u64` counter that only goes up and survives every
migration. For each V2 request it:

1. hashes the next counter value into an id, `sha256("verify_foreign_tx_v2" || counter)`,
2. creates the yield under that id with `promise_yield_create_with_id`,
3. stores the request, the hash of its expected values and the current block height under
   the id, and hands the id to the timeout callback.

- **Prefix.** All yields of one account share a namespace, so the prefix keeps V2 ids apart
  from ids the contract may pick for other yields later.
- **Collision.** The create call returns `None` if a yield with that id is still pending. A
  fresh counter value can't collide, so if it ever happens, we fail the request as a bug.
- **Resume.** The respond method resumes the yield with `promise_yield_resume_with_yield_id`.
- **Encoding.** Ids are hex encoded in the event and the response.
- **Protocol.** All of this needs NEAR protocol version 85, which mainnet already runs.

**How nodes learn the id.** In the same call, the contract emits the id as a
[NEP 297](https://github.com/near/NEPs/blob/master/neps/nep-0297.md) event, using the
`#[near(event_json(...))]` macro from `near-sdk`:

```rust
#[near(event_json(standard = "mpc"))]
enum MpcContractEvent {
    #[event_version("1.0.0")]
    VerifyForeignTxV2YieldCreated { yield_id: YieldId },
}
```

`emit()` writes one line through `env::log_str`:

```text
EVENT_JSON:{"standard":"mpc","version":"1.0.0","event":"verify_foreign_tx_v2_yield_created","data":{"yield_id":"…"}}
```

That line is stored on chain in the `logs` of the call's execution outcome. The node's indexer
already looks at every receipt the MPC contract executes, to find new requests. For a
`verify_foreign_transaction_v2` call, it now also reads that receipt's `logs`:

1. Keep the lines that start with `EVENT_JSON:` and parse the JSON after the prefix.
2. Keep the events with the contract's standard and the `verify_foreign_tx_v2_yield_created`
   event name, at a version the node supports.
3. Require exactly one, and store its yield id with the request, together with the height of
   the block being indexed. With none or several, skip the request, as it does today for
   arguments it can't parse.

Nodes need no extra RPC call for this. A caller can't fake the event, because only the MPC
contract's own code can write logs into its receipts. This is the first contract log nodes
read, and the contract's other logs stay as messages for people.

A new respond method for attested participants:

```rust
fn respond_verify_foreign_tx_v2(
    yield_id: YieldId,
    outcome: ForeignTxVerificationOutcome,
    signature: SignatureResponse,
)
```

This method:

1. Looks up the request stored under `yield_id`, and fails with `RequestNotFound` if there is
   none.
2. Rebuilds the payload hash from the stored request, expected values hash and block height,
   the yield id and the outcome.
3. Verifies the signature with the key of the request's `domain_id`.
4. Resumes that yield with a `VerifyForeignTransactionResponseV2`, and removes the entry.

**This stops replay.** In V1, one signed response answers every pending (not expired) request
with the same arguments. That is fine for a success, but wrong for _not found_ once the
transaction lands. A V2 signature names a single yield, which is removed as soon as it is
answered, so the signature can't be used again.

**Honest nodes only sign while the request is open.** This rule is the same as for today's
requests. What is new is that a V2 signature includes `request_block_height`, so a receiver
outside NEAR can check that window too.

**One signature, one request.** Identical requests made at the same time each get their own
signing round, since nodes queue them by receipt id.

### Node outcomes

Every node that supports the chain inspects a V2 request once the request's block is final, so
a fork can't hand two requests the same yield id. It retries transient provider errors within its 5 second inspection cap, signs its node outcome
once, and sends it to every other participant. The leader inspects too, and its outcome counts
like any other.

**Outcome keys.** Every node generates a dedicated Ed25519 key pair for node outcomes, its
**outcome key**, separate from and independent of its TLS key pair. The node registers the
public key with the contract, in a call signed with its attested account key, the same check
the respond methods use. So only the attested node can set it. The contract keeps one outcome
key per participant account, and a node registers again to replace it, for example after a
node migration. Every node reads the keys from the contract to check other nodes' outcomes.

```rust
struct NodeOutcomeStatement {
    yield_id: YieldId,
    signer: ParticipantId,
    outcome: NodeOutcome,
}

enum NodeOutcome {
    Verdict(NodeVerdict),
    NoVerdict(NoVerdictReason),
}

enum NodeVerdict {
    Verified,
    Negative(ForeignTxVerificationNegativeVerdict),
}

enum NoVerdictReason {
    Transient,
    InspectorsDisagree,
}
```

A node signs the prefix `near-mpc foreign tx v2 node outcome` followed by the Borsh encoded
statement.

- **One outcome per node and request.** An honest node signs a single statement for a yield,
  and never inspects that request again. A transaction that isn't final yet can end
  inconclusive, and the caller asks again later. Nodes don't store statements, so a node that
  restarts may inspect again and sign a second one.
- **Every node gets every outcome.** A statement is about 100 bytes, so sending it to all
  participants is cheap. Any acting leader, including a backup that takes over, then holds the
  same evidence.
- **Outcomes can arrive before the request.** A node keeps an outcome for a request it hasn't
  indexed yet for up to 3 seconds (5 blocks), one per sender and yield id, and for at most
  256 such yield ids per sender.

### Deciding and signing

**Acting leaders.** An acting leader is a node the request queue lets lead the request now,
in the view of the node that checks: the first node eligible to lead it, or a backup whose
turn has started. A node times a backup's turn from its own index time, and accepts it up
to 3 seconds (5 blocks) early, to allow for indexer lag.

**The counting rule.** Let s be the number of nodes that support the chain and t the signing
threshold. From the signed outcomes it holds, an acting leader counts, for each verdict, how
many nodes signed it, and how many nodes it hasn't heard from yet.

- **Verdict.** When t nodes signed the same verdict, the leader signs that verdict. If two
  verdicts reach t, which needs s ≥ 2t, it signs the first.
- **Inconclusive.** When no verdict can reach t, even if every node not yet heard from signed
  it, the leader signs an inconclusive. For example, transient errors from s − t + 1 nodes, or
  a split where no verdict and the missing nodes together make t.
- **Otherwise** the leader waits for more outcomes, until the request closes.

Each node counts once. A node that signed two different outcomes for one yield counts as
heard, but for no verdict, and takes part in no round. The leader logs both statements. They
show a faulty or restarted node, not necessarily a malicious one.

![Deciding: an acting leader counts signed node outcomes. When t nodes signed the same verdict, it runs a signing round for that verdict with an asset among those nodes. When no verdict can reach t, it runs a signing round for the inconclusive. Otherwise it waits for more outcomes, and the request times out if they never come. A round that fails is retried with a fresh asset while rounds remain. Then this leader stops, and the request times out unless another leader answers.](attachments/decision.png)

**The signing round.** The leader sends Start with the outcome and its evidence: the signed
statements that meet the counting rule.

1. **Asset.** For a verdict, every participant of the asset signed that verdict. For an
   inconclusive, every participant sent an outcome. So every signer has indexed the request.
   If no such asset is free, the leader waits for one, and the wait doesn't use up a round.
   A leader is part of every asset it owns, so a leader that didn't sign the verdict stops,
   and a backup leads.
2. **Signers check.** A signer joins only if:
   - the request is open in its view,
   - the sender is an acting leader in its view,
   - every statement in the evidence verifies against its signer's outcome key on chain, and
     names this yield id,
   - the evidence meets the counting rule for the outcome and includes the signer's own
     statement, for a verdict that same verdict, and
   - it has joined fewer than three rounds for this request and leader.

   Otherwise it refuses with the network abort. Signers don't need their own count to agree
   with the leader's. The evidence is enough.
3. **Retries.** A round has a 5 second deadline, a target until load tests confirm it. A
   refusal, a silent signer or a share that doesn't combine fails the round. The leader then
   retries with a fresh asset, preferring one without the nodes that failed it, up to three
   rounds. After the third it stops. A retry never repeats an inspection, because the evidence
   stays valid.

Sign, CKD and V1 keep their attempt deadline of 60 seconds and their limit of ten attempts.

**What inconclusive means.** The nodes disagreed about the transaction, or transient errors kept too many
of them from reaching a verdict. To a caller both lead to the same next step, so both are
reported the same way: the network couldn't decide right now, and the caller may try again.
Each inconclusive raises a metric labelled with its cause and the chain, and the leader logs
the evidence. The outcomes can't show whether a node lags or lies, so the logs show where to
look, not who is malicious.

**Why only acting leaders.** Today followers accept Start from any participant. Without the
leadership check, any node could race the honest leader and use up assets on its requests.

**When there is no decision.** Silent nodes send no outcome. If too many stay silent for any
outcome to meet the counting rule, the request times out.

**How long a request takes.** Times count from the moment the leader holds enough outcomes for
the counting rule. Each node's outcome arrives within its indexer lag, at most 5 seconds of
inspection, and one message within the cluster. The times leave out any wait for an asset and
the time for the response to land on NEAR. The worst cases assume that each round runs to its
5 second deadline and 1 second passes before each new round.

| Scenario | How the request ends | Time to the answer | Answer |
|---|---|---|---|
| t nodes reach the same verdict | The first round signs | At most 5 seconds | Success or negative verdict |
| Some nodes differ, or report transient errors, but t still agree | The same, with an asset among the t | At most 5 seconds | Success or negative verdict |
| A signer is silent, refuses, or sends a bad share | The next round uses a fresh asset | At most about 17 seconds for three rounds | The same outcome |
| No verdict can reach t | The inconclusive round | At most 5 seconds, 17 if it takes three rounds | Inconclusive |
| Too many nodes stay silent to decide | The yield times out | 200 blocks, about 120 seconds | None |
| Any failure in V1 today | The yield times out | 200 blocks, about 120 seconds | None |

---

## Q&A

Questions about design choices: the options considered and why one was chosen.

### Why a new request method?

V1 must not change, so V2 has to be opt in.

- **A. Extend V1 in place.** Changes every V1 payload hash.
- **B. A `payload_version` flag on the existing method.** Needs a hand written deserializer
  and JSON schema, and breaks every existing construction of the V1 arguments.
- **C. A new method with its own request type (chosen).** `VerifyForeignTransactionRequestV2`
  is what the caller passes and what the contract stores under the yield id.

C leaves every V1 caller untouched, and gives V2 its own types from end to end. V2 needs that,
since it changes more than request processing: the payload, the response and how nodes agree
on an outcome.

### Why does the contract pick the yield id?

Every V2 request needs its own id: nodes sign it, the respond method finds the request using
it, and the timeout callback uses it to remove exactly that request.

`promise_yield_create` only creates its id after the callback's arguments are fixed, so the
callback can never know it. That's why a V1 timeout simply removes the oldest yield for the
same request. Since we need to define a new id anyway, `promise_yield_create_with_id` lets us
use it as the yield id.

Nodes must know each request's `yield_id`. The contract announces it in an event, because
that is the only place nodes can read it from:

- **Not in the call's arguments.** Nodes find a new request by reading the arguments the
  caller passed. The contract creates the `yield_id` only while the call runs, so the caller
  can't include it.
- **Not in the call's result.** The result of a V2 call is the answer to the request, which
  comes later. Nodes need the `yield_id` before that, to produce the answer.
- **In the call's logs.** The contract writes the `yield_id` into its logs as an event while
  the call runs. The logs are in the same block the node already reads for the request, so
  the node gets the request and its `yield_id` together, without an extra lookup.

### Why collect node outcomes before signing?

- **A. Inspect and sign in one attempt, as V1 does.** The asset fixes the t nodes before
  anyone inspects. One node that differs or has a provider error fails the attempt, so the
  leader retries, and every retry uses up an asset and inspects again.
- **B. Collect signed outcomes from every node first, then sign (chosen).** The leader picks
  the asset once it knows which nodes agree.

B costs one more message round within the cluster, about 200 ms, against a P90 response time
of 5.58 seconds today. In return it needs no inspection retries, uses at most three assets per
leader, and one node that differs or has a provider error no longer blocks a verdict. Every
answer comes with evidence a signer can check.

This works for foreign transactions because the inspection comes before any cryptography, so
the leader can pick the asset afterwards. For sign requests there is nothing to collect first,
and a larger signing set would need triples for more nodes.

### Which key signs node outcomes?

- **A. The TLS key.** Already on chain, but one key would then sign for two purposes.
- **B. The node's share of a threshold key.** Needs each node's public key share, which the
  current DKG doesn't keep, and uses that key for a second purpose too.
- **C. A dedicated Ed25519 key pair per node, registered with the contract (chosen).** The
  same plain signature scheme as TLS, with no cryptography changes, and no change to
  participant info or attestations.

### How does V2 behave when the leader changes?

V2 relies only on the request queue's answer to who may lead right now (see "Deciding and
signing"). Every node sends its outcome to every participant, so a backup holds the same
evidence as the leader and signs without inspecting again. This has two costs.

- Nodes can disagree on who may lead. While they do, signers refuse the leaders they don't
  accept, and every refused round counts against that leader, so a request can time out if
  the network stays partitioned for long enough time.
- A backup can start while a slow leader is still trying. With four planned leaders, each
  with three rounds, a request can use up to 4 × 3 = 12 assets instead of 3 with a single
  leader.

### How does V2 roll out?

V1 stays untouched, so no upgrade order breaks existing callers.

- **Outcome keys come first.** The contract gets the method to register outcome keys, and
  every node registers one before V2 is enabled.
- **P2P needs one protocol version bump**, for the signed node outcome as a new message kind,
  and for the signing round with evidence as a new task kind. Aborts reuse the existing
  message.
- **The V2 method ships in its own contract release**, once every node supports V2 and has an
  outcome key on chain. Until then, old nodes would ignore V2 requests and they would time out.

---

## Security analysis

We assume, as V1 does, that fewer than t nodes are malicious, where t is the signing
threshold.

| Threat | Defense |
| --- | --- |
| Malicious leader forges a verdict | A verdict needs t node outcomes for it, each signed with an outcome key, so at least one comes from an honest node. Every signer also signed that verdict itself. |
| Leader asks to sign for a request that doesn't exist | Honest nodes only sign for requests their own indexer has seen. |
| Old _not found_ replayed after the transaction lands | Each signature is tied to one request, which is closed once it is answered. A new request gets its own check. |
| Signature replayed on another caller's request | The signature names its yield id, and the contract only answers that yield. |
| Old _not found_ relayed off NEAR later | The signature carries the request's block height, and honest nodes only sign within 200 blocks of it. The receiver can see how old the answer is. |
| Two different outcomes signed for one yield | Honest nodes sign one outcome each, so two leaders can hold evidence for different outcomes only if some node signed two, or if s ≥ 2t and two verdicts each reach t. The contract takes the first and rejects the other, but the rejected signature stays public on chain. |
| Leader reruns an answered or expired request | Honest nodes refuse to join once their indexer shows the request answered or older than 200 blocks. |
| Responder submits a signature with a different outcome | The contract rebuilds the hash from the submitted outcome, and rejects the response if the signature doesn't match. |
| Provider details split honest nodes | Negative verdicts carry no provider data, so honest nodes sign the same bytes. |
| Faulty provider drives a verdict | Blocked as long as the node's other providers answer, because they would disagree. If they are all down, the faulty provider decides that node's outcome. It drives a verdict only if it decides the outcome at t nodes, just as it can drive a success today. |
| Node forces an inconclusive | The evidence must show that no verdict can reach t. Leaving statements out only makes that harder to show, so a leader can't hide outcomes to force it. Fewer than t malicious nodes can force it only when the honest nodes themselves don't reach t on one verdict. |
| Signer refuses, goes silent or sends a bad share | Fails that round, and the leader retries with an asset without that node when it can. The node's outcome still counts, so it can't block the decision. |
| Malicious leader uses up assets on a request it leads | A signer joins at most three rounds per request and leader, only from acting leaders, and only with evidence. A leader can only use assets it owns. |
| Leader forges or replays another node's outcome | Node outcomes are signed with each node's outcome key and name the yield id, so a leader can't forge them or reuse them for another request. Any acting leader may use them for the same request, which is intended. |
| Node signs two different outcomes for one yield | It counts for no verdict and takes part in no round. The leader logs both statements. |
| A node that isn't an acting leader sends Start | Signers refuse it, since it isn't an acting leader in their view (see "Deciding and signing"). |
| Caller plants a fake yield id | Nodes read the id only from the log of the MPC contract's own V2 receipt. Only the contract's code can log there, and it logs only the id it generated. |
| Late timeout removes an open request | Each request is stored under its own yield id, and a timeout only removes its own entry. |
| Node overstates its indexer height to lead more | Not new. V2 uses the queue's leader rule unchanged. Such a node can already let those requests time out. |
| Caller floods requests the network can't decide | Every node that supports the chain inspects each request, where V1 only has an asset's t nodes inspect, and each request can use up to three assets per leader, where a sign request uses one for the same deposit. We accept that as the cost of signing every answer. |
| Caller trusts the outcome label | On NEAR the contract checked the signature over the caller's own expected values hash, so the label is safe to trust. Outside NEAR the receiver must check the signature (see "Payload and response types"). |
| Caller states wrong expected values | Nodes sign the negative verdict `ValuesMismatch`. It answers only that request. |

---

## Worked examples

- **One divergent node F on an honest network.** F's outcome differs from the others, but t
  other nodes agree, so the leader signs their verdict with an asset without F. F only shows
  up in the logs.
- **A transaction lands during the request.** Some nodes' providers already have the block and
  report success. Others haven't seen it yet and report _not found_. If t nodes agree on one,
  that is the answer. Otherwise the request ends with an inconclusive, and the caller asks
  again.
- **Provider outage.** Each node retries its providers within the inspection cap, then reports
  transient errors. As soon as s − t + 1 nodes have reported them, the caller gets an
  inconclusive instead of a timeout.
- **Malicious follower M.** If M signs a false node outcome, the honest nodes still reach t
  without it, and the verdict's asset leaves M out. If M signs two different outcomes, it
  counts for no verdict. If M only refuses or stays silent in a round, the leader retries with an
  asset without M.
- **Eve steers a copy of Bob's request to a malicious leader M.** Eve wants a false answer
  about Bob's transaction, or to block Bob's request. A request's leaders follow from a hash
  of its receipt id, which Eve can't pick, but she can submit identical copies of Bob's
  request until one of them lands on M. What M can and cannot do with that copy:
  - **Can let it time out**, as its leader, until a backup's turn starts.
  - **Cannot get a false verdict or an unfounded inconclusive signed**, for the copy or any
    other request (Security analysis, "Malicious leader forges a verdict" and "Node forces
    an inconclusive").
  - **Gains nothing on Bob's request.** Any answer names the copy's yield id, and the
    contract only answers that copy. M can't run a round for Bob's request either, unless it
    acts as one of Bob's leaders, which Eve's copies don't change.

  So steering a request to M gets Eve at most a delay on her own copy, which is no worse than
  today. Each copy costs her a transaction, and costs the network an inspection at every node.
