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
- V2 attempts fail fast. Each follower signs what it found and sends it to the leader with its
  share, so the leader ends a failed attempt at the first sign of trouble instead of waiting
  out the deadline.
- Only an acting leader (Component 3) can get the network to sign an inconclusive, and only
  with signed node outcomes as evidence.

## Vocabulary

The doc uses these terms for the levels of an answer, from the bottom up.

| Term | Who | Meaning |
|---|---|---|
| Verdict | One inspector, so one provider | What one provider says about the transaction: found, with the extracted values, or a negative verdict such as not found. |
| Node outcome | One node | What one node concludes from its verdicts, after retrying transient errors: a verdict all its answering inspectors agree on, checked against the caller's expected values, or no verdict, because of transient errors or because its inspectors disagree. Every node signs its node outcome, and a follower sends it to the leader. A node that does not inspect at all, for example because the request is closed, refuses, and a refusal is not a node outcome. |
| Attempt result | The leader | What the leader does with the node outcomes: sign when they all match, end the request with an inconclusive when two nodes' verdicts differ or a node's inspectors disagree, and retry in every other case. |
| Signed outcome | The network | The answer the caller gets: success, negative verdict, or inconclusive. |

---

## Architecture

Callers talk to the contract as they do today. What changes is what the nodes sign, and when
they stop trying.

![Overview: the caller sends a V2 request with the values it expects. The contract stores the request, the hash of the expected values and the block height under a yield id it picks, and emits the id. The leader takes an asset if needed and sends Start. Everyone inspects, and followers return their signed outcome with their share. The signature over the request, its block height, the yield id and the outcome goes back to the contract, which returns the response with the signature and the outcome to the caller. When nodes disagree, or after the last attempt, the leader runs the inconclusive round with signed evidence, and its signature also answers only that yield.](attachments/overview.png)

1. **Request.** The caller calls `verify_foreign_transaction_v2` with the values it expects.
   The contract picks a yield id, stores the request, the hash of the expected values and the
   current block height under it, and announces the id in an event. Every node's indexer picks
   up the request and the id together.
2. **Start.** The leader takes an asset if needed and sends Start. A node takes part only while
   the request is unanswered, inside its 200 block window, and the sender is an acting leader
   in its view (Component 3).
3. **Inspect.** The leader and followers inspect in parallel. Every node signs what it found,
   and each follower sends it to the leader, followed by its share if it found a verdict.
4. **Sign or fail.** If all node outcomes match, the shares combine into a signature. If
   nodes disagree, the request goes straight to the inconclusive. Otherwise the leader
   retries.
5. **Inconclusive.** When nodes disagree, or enough nodes report transient errors, the leader
   runs one more round to sign an inconclusive for the request. Signers only join if the node
   asking is an acting leader and shows signed evidence.
6. **Respond.** The leader submits the yield id, the outcome and the signature. The contract
   looks up the request, rebuilds the hash, checks the signature and resumes that yield.

### Component 1: payload and response types

```rust
struct NearBlockHeight(u64);
struct YieldId([u8; 32]);                          // picked by the contract, see Component 2

enum ForeignTxSignPayload {
    V1(ForeignTxSignPayloadV1),                    // unchanged
    V2(ForeignTxSignPayloadV2),
}

struct ForeignTxSignPayloadV2 {
    request: ForeignChainRpcRequest,
    expected_values_hash: Hash256,                 // sha256 of the Borsh encoded expected values
    request_block_height: NearBlockHeight,         // the block the request's yield was created in
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
  its 5 second inspection cap. If its inspectors still give no verdict, it reports no verdict
  for that attempt. If its inspectors disagree, it reports that, and the request ends with an
  inconclusive, because a disagreement is final (see
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
    request_block_height: NearBlockHeight,
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

### Component 2: yields and the respond method

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
attempt, since nodes queue them by receipt id.

### Component 3: attempts that fail fast

Today a follower that fails before signing sends nothing, and the leader waits out the
attempt deadline. A V2 attempt runs like this:

1. **Open.** The leader takes an asset if needed and sends Start right away, without waiting
   for its own inspection. The asset's participants must all be within the indexer margin. So
   every attempt uses up an asset, even one that fails. V1 inspects first, so a bad request
   costs no asset. V2 gives that up for the fastest happy path.
2. **Inspect.** Everyone inspects in parallel. A node retries transient provider errors within
   its local 5 second inspection cap.
3. **Report.** Each follower signs its node outcome and sends it to the leader: a verdict
   followed by its share, or no verdict with the reason. It sends its outcome even after the
   attempt ends, so evidence builds up. The leader counts an outcome only from a node in that
   attempt. A follower refuses with the network abort, without inspecting, when:
   - the request is closed,
   - it hasn't indexed the request within 3 seconds of receiving Start,
   - the sender isn't an acting leader of the request in its view, or
   - it has already joined three attempts for this request and leader.
4. **Fail fast.** The leader ends the attempt as soon as:
   - two node outcomes differ, between two followers or between a follower and the leader, or
   - a node, including leader nodes, has no node outcome: it reports no verdict, or it
     refuses.

   Neither waits for the deadline. As today, a share that doesn't combine, or a follower silent
   past the deadline, also fails the attempt.

What happens next depends on why the attempt ended:

| Why the attempt ended | Next |
|---|---|
| Two nodes' verdicts differ, or a node's inspectors disagree, the leader's included | The request ends with an inconclusive at once (Component 4). A disagreement is never retried. |
| A node, the leader included, has no verdict because of transient errors | The leader retries. Once its evidence holds transient errors from s − t + 1 nodes, it asks for the inconclusive instead (Component 4). |
| A follower refuses, goes silent, or its share fails after every node agreed | The leader retries. This is a problem within the cluster, not a finding about the transaction, so it is never evidence. |

**Acting leaders.** An acting leader is a node the request queue lets lead the request now,
in the view of the node that checks: the first node eligible to lead it, or a backup whose
turn has started. A follower times a backup's turn from its own index time, and accepts it up
to 3 seconds early, the same margin it has to index a request.

**Signed node outcomes.** Every node signs its node outcome as a `NodeOutcomeStatement`, with
the Ed25519 key of its TLS identity. A leader keeps the statements from its attempts for a
yield. These statements are its **evidence** when it asks for an inconclusive (Component 4).

```rust
struct NodeOutcomeStatement {
    yield_id: YieldId,
    leader: ParticipantId,
    attempt: AttemptId,                // unique per attempt
    signer: ParticipantId,
    outcome: NodeOutcome,
}

enum NodeOutcome {
    Verdict(ForeignTxVerificationOutcome),
    NoVerdict(NoVerdictReason),
}

enum NoVerdictReason {
    Transient,
    InspectorsDisagree,
}
```

A node signs the prefix `near-mpc foreign tx v2 node outcome` followed by the Borsh
encoded statement. Refusals are not signed. They are problems within the cluster, not
findings, so they stay the plain network abort and never count as evidence.

**Attempt deadline: 13 seconds from Start.** That is 3 seconds (5 blocks) for a follower's
indexer to pick up the request, 5 seconds for inspection, and 5 seconds for the network
communication within the cluster. These are targets until load tests confirm them. V1 keeps
its default of 60 seconds.

If no suitable asset is available, the leader waits for one before Start. The wait is outside
the attempt deadline and doesn't use up an attempt. A request that gets no asset within its
window times out.

**Indexer margin: 5 blocks.** The V2 leader only takes an asset whose participants are all
within 5 blocks of its own indexer. A mainnet block takes about 0.6 seconds, so the 3 second
wait covers 5 blocks. Today an asset may include a node 50 blocks behind the leader, which
would miss that wait. In mainnet samples from 30 September to 7 October 2026, an online node's
indexer was within 5 blocks of the most advanced one 99.94% of the time.

![Attempts: matching node outcomes sign the attempt. A disagreement goes straight to the inconclusive round. A node without a verdict because of transient errors adds signed evidence, and once the evidence holds transient outcomes from s − t + 1 nodes, the leader runs the inconclusive round. Until then, and after a refusal, a silent follower or a bad share, the leader retries while attempts remain. Then it stops, and the request times out unless another leader answers.](attachments/attempts.png)

**Retries: up to three attempts per leader.** The leader retries at once after a failed
attempt, preferring a free asset without the nodes that just reported transient errors,
refused or stayed silent.

- **Only cluster problems and transient provider errors are retried.** A disagreement ends the
  request at once, and so do transient errors from s − t + 1 nodes.
- **A follower joins at most three attempts per request and leader.** This bounds the assets
  one leader can use up. A new leader starts its own attempts.
- **A transaction that isn't final yet ends inconclusive.** The caller asks again later.
- **Sign, CKD and V1 keep their limit of ten.**

Component 4, "How long a request takes", lists the time for each case.

### Component 4: the signed inconclusive

1. **The leader runs one more signing round**, this time over a V2 payload whose outcome is
   `Inconclusive`. The payload only depends on the request, its expected values hash, its
   block height and the yield id, so every signer derives the same hash, and only a missing or bad
   share can fail the round.
2. **Signers check the leader and the evidence.** A node signs this round only if the request
   is still open and the node asking is an acting leader in its own view (Component 3).

   The node asking sends its evidence with the round's Start. A signer checks each
   `NodeOutcomeStatement` against the TLS key of the node that signed it. It joins only if the
   evidence shows one of these:
   - Two different nodes signed different verdicts in the same attempt.
   - One node's inspectors disagreed.
   - At least s − t + 1 different nodes reported transient errors, where s is the number of
     nodes that support the chain and t is the signing threshold. Then fewer than t nodes
     answered without a transient error, too few to sign a verdict.

   A disagreement ends the request at once (Component 3). Transient errors can build up over
   several attempts, the leader starts the inconclusive signing round as soon as s − t + 1 nodes have reported
   transient errors. A transient error report counts even if it arrives after its attempt ended.

   Signers don't check how many attempts the leader made, only the evidence.

3. **Up to three rounds.** Like the attempts, the inconclusive gets three rounds, to ride out a
   flaky network. Each round has a fresh asset and a 5 second deadline, which is also a target
   until load tests confirm it. A signer joins at most three rounds per request and leader. If
   all three fail, this leader stops.
4. **The contract resumes that yield**, and the caller gets `Inconclusive {}`.

**What inconclusive means.** The nodes disagreed about the transaction, or transient errors kept too many
of them from reaching a verdict. To a caller both lead to the same next step, so both are
reported the same way: the network couldn't decide right now, and the caller may try again.
Each inconclusive raises a metric labelled with its cause, the chain and, for a disagreement,
the two nodes. The leader also logs their signed outcomes. The outcomes can't show whether a
node lags or lies, so the metric shows where to look, not who is malicious.

**Why only acting leaders.** Today followers accept Start from any participant. Without the
leadership check, one malicious node could end any request before its honest leader answers.

**When there is no evidence.** Silence, refusals, bad shares and "transient outcomes from too
few nodes" leave nothing to show for evidence, so the leader stops after its attempts, and the request times
out unless another leader answers.

**How long a request takes.** Times count from the first leader's first Start and assume it
stays an acting leader. They leave out any wait for an asset and the time for the response to
land on NEAR. Other acting leaders can only end a request sooner. The worst cases assume that
each attempt runs to its 13 second deadline, the inconclusive takes three rounds of 5 seconds,
and 1 second passes before each new attempt or round.

| Scenario | How the request ends | Time to the answer | Answer |
|---|---|---|---|
| Every node reaches the same verdict | The first attempt signs | At most 13 seconds | Success or negative verdict |
| A follower disconnects, stays silent, or its providers keep failing | The next attempt can use an asset without it | At most about 14 seconds more | Success or negative verdict |
| Nodes, or the inspectors of one node, disagree | The first mismatch ends the attempt, then the inconclusive | At most about 31 seconds if the first attempt finds it, about 59 if the third does | Inconclusive |
| Attempts reach s − t + 1 nodes with provider errors | The inconclusive as soon as the evidence holds that many | At most about 31 seconds if one attempt is enough, about 59 if it takes three | Inconclusive |
| A silent follower is in every asset the leader can use | The leader can't prove silence. A backup with an asset that leaves the follower out can still answer | Up to 200 blocks, about 120 seconds | The verdict, or none |
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
since it changes more than request processing: the payload, the response and how nodes run
attempts.

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

### When does the network give up?

Nodes fail to answer for two kinds of reasons: they disagree about the transaction, or
something breaks within the cluster or at a provider. Only the second kind is worth a retry.

- **A. After one failed attempt.** Gives up on requests a single retry would have completed,
  for example after a provider blip.
- **B. Retry every failure up to the budget.** Retries disagreements that should end the
  request at once.
- **C. End a disagreement, or transient errors at too many nodes, at once, retry everything
  else up to three attempts, and require signed node outcomes as evidence for the inconclusive
  (chosen).**

C keeps a disagreement final and a failed request short. It needs signed node outcomes, which
use each node's existing TLS key. Every inconclusive comes with evidence, and a metric can
show the nodes involved.

### How does V2 behave when the leader changes?

V2 relies only on the request queue's answer to who may lead right now (Component 3). This has
two costs.

- Nodes can disagree on who may lead. While they do, followers refuse the leaders they don't
  accept, and every refused attempt counts against that leader, so a request can time out if
  the network stays partitioned for long enough time.
- A backup can start while a slow leader is still trying. With four planned leaders, each with
  three attempts and three rounds, a request can use up to 4 × (3 + 3) = 24 assets instead of
  only 6 (3 + 3) with a single leader.

### How does V2 roll out?

V1 stays untouched, so no upgrade order breaks existing callers.

- **The V2 method ships in its own contract release**, once every node supports V2. Until
  then, old nodes would ignore V2 requests and they would time out.
- **P2P needs one protocol version bump**, for the follower's signed node outcome as a new
  message kind, and for the inconclusive round as a new task kind. Aborts reuse the existing
  message.

---

## Security analysis

We assume, as V1 does, that fewer than t nodes are malicious, where t is the signing
threshold.

| Threat                                                 | Defense                                                                                                                                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious leader forges a verdict                      | Every follower checks the transaction itself, and shares signed over different outcomes don't combine into a signature.                                                                       |
| Leader asks to sign for a request that doesn't exist   | Honest nodes only sign for requests their own indexer has seen.                                                                                                                               |
| Old _not found_ replayed after the transaction lands   | Each signature is tied to one request, which is closed once it is answered. A new request gets its own check.                                                                                 |
| Signature replayed on another caller's request         | The signature names its yield id, and the contract only answers that yield.                                                                                                                   |
| Old _not found_ relayed off NEAR later                 | The signature carries the request's block height, and honest nodes only sign within 200 blocks of it. The receiver can see how old the answer is.                                             |
| Two different verdicts signed for one yield            | A backup and a slow leader can check at different times, and get for example _not found_ and then success. The contract takes the first and rejects the other, but the rejected signature stays public on chain. Both are honest checks, and a _not found_ never proves that the transaction won't land later. |
| Leader reruns an answered or expired request           | Honest nodes refuse to join once their indexer shows the request answered or older than 200 blocks.                                                                                           |
| Responder submits a signature with a different outcome | The contract rebuilds the hash from the submitted outcome, and rejects the response if the signature doesn't match.                                                                           |
| Provider details split honest nodes                    | Negative verdicts carry no provider data, so honest nodes sign the same bytes.                                                                                                                |
| Faulty provider drives a verdict                       | Blocked as long as the node's other providers answer, because they would disagree. If they are all down, the faulty provider decides that node's outcome, and other nodes would disagree. Only a provider that decides the outcome at every node in an attempt can drive a verdict, just as it can drive a success today. |
| Follower refuses, goes silent or sends a bad share     | Fails that attempt, and the leader retries. When it can, it uses an asset without a follower that refused or stayed silent (Component 3). None of these is evidence for an inconclusive, so a request can time out if every attempt includes that follower. |
| Node forces an inconclusive                            | A follower can end any request whose attempt includes it, where V1 would retry (Component 3). An acting leader can end any request it leads, which it could already let time out (Component 4, step 2). Only liveness is affected, and the metric records the nodes involved. |
| Malicious leader uses up assets on a request it leads  | A follower joins at most three attempts and three inconclusive rounds per request and leader, and only from acting leaders. A leader can only use assets it owns.                             |
| Leader forges or replays another node's outcome        | Node outcomes are signed with each node's attested TLS key and name the yield id, the leader and the attempt. So a leader can't forge them or reuse them for another request or leader. Each node counts once toward the evidence. |
| Node outside an attempt sends an outcome               | The leader counts an outcome only from a node in that attempt (Component 3).                                                                                                                  |
| A node that isn't an acting leader sends Start         | Followers and signers refuse it, since it isn't an acting leader in their view (Components 3 and 4).                                                                                          |
| Caller plants a fake yield id                          | Nodes read the id only from the log of the MPC contract's own V2 receipt. Only the contract's code can log there, and it logs only the id it generated.                                       |
| Late timeout removes an open request                   | Each request is stored under its own yield id, and a timeout only removes its own entry.                                                                                                      |
| Node overstates its indexer height to lead more        | Not new. V2 uses the queue's leader rule unchanged. Such a node can already let those requests time out, and in V2 end them inconclusive instead (Component 4).                               |
| Caller floods requests the network can't decide        | Every attempt and inconclusive round uses an asset, so such a request uses up to six per leader, where a sign request uses one for the same deposit. We accept that as the cost of signing every answer. |
| Caller trusts the outcome label                        | On NEAR the contract checked the signature over the caller's own expected values hash, so the label is safe to trust. Outside NEAR the receiver must check the signature (Component 1).       |
| Caller states wrong expected values                    | Nodes sign the negative verdict `ValuesMismatch`. It answers only that request.                                                                                                               |

---

## Worked examples

- **One divergent node F on an honest network.** When an attempt includes F, F's node outcome
  differs from another node's, so the request ends with an inconclusive at once, and F is one
  of the two nodes in each disagreement. Today a retry without F can succeed, but in V2 a
  disagreement is final. When the asset excludes F, the request succeeds at once.
- **A transaction lands during the request.** One node's provider already has the block and
  reports success. Another node's provider, or another provider of the same node, hasn't seen
  it yet and reports _not found_. The request ends with an inconclusive, and the caller asks
  again.
- **Provider outage.** Each node retries its providers within the inspection cap, then reports
  transient errors. As soon as s − t + 1 nodes have reported them, the caller gets an
  inconclusive instead of a timeout.
- **Malicious follower M.** If M signs a false node outcome, every request whose attempt
  includes M ends in an inconclusive, where V1 would retry. Its outcomes look the same as those
  of a node whose provider lags. M is one of the two nodes in each of these disagreements. If M
  only refuses or stays silent, the leader retries with an asset without M when it can, so a
  request times out only if every attempt includes M.
- **Eve steers a copy of Bob's request to a malicious leader M.** Eve wants a false answer
  about Bob's transaction, or to block Bob's request. A request's leaders follow from a hash
  of its receipt id, which Eve can't pick, but she can submit identical copies of Bob's
  request until one of them lands on M. What M can and cannot do with that copy:
  - **Can end it with an inconclusive**, as its leader (Component 4, step 2), which costs
    only liveness on Eve's own copy.
  - **Cannot get a false verdict signed**, for the copy or any other request (Security
    analysis, "Malicious leader forges a verdict").
  - **Gains nothing on Bob's request.** The inconclusive names the copy's yield id, and the
    contract only answers that copy. M can't run an inconclusive round for Bob's request
    either, unless it acts as one of Bob's leaders, which Eve's copies don't change.

  So steering a request to M gets Eve at most a timeout or a signed inconclusive on her own
  copy, which is no worse than today. Each copy costs her a transaction and costs the network
  an asset.
