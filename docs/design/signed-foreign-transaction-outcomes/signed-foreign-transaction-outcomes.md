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
- **Inconclusive:** the nodes disagreed, or the network could not reach an answer within its
  attempt budget. It says nothing about the transaction.

If the network can't sign at all, the request still times out.

In short:

- Callers opt in through a new method, `verify_foreign_transaction_v2`. V1 is unchanged.
- Every V2 answer is tied to the one request it answers. It can't be reused for any other
  request, so an old _not found_ can never answer a newer one.
- Every V2 answer also records the block the request was made in, and nodes only sign within
  200 blocks of it. Anyone who receives the signature later, even outside NEAR, can tell when
  the network checked.
- The caller states the values it expects. Nodes check them, so a success means the values
  the caller asked for.
- V2 attempts fail fast. Each follower signs what it found and sends it to the leader with its
  share, so the leader ends a failed attempt at the first sign of trouble instead of waiting
  out the deadline.
- When nodes disagree, or the leader runs out of attempts, the leader coordinates signing for
  an inconclusive response payload. Only the request's leader can do this, and only with
  signed evidence from its followers.

## Vocabulary

The doc uses these terms for the levels of an answer, from the bottom up.

| Term | Who | Meaning |
|---|---|---|
| Verdict | One inspector, so one provider | What one provider says about the transaction: found, with the extracted values, or a negative verdict such as not found. |
| Node outcome | One node | What the node concludes from all its verdicts, after it retried transient errors. Either a verdict that every answering inspector agrees on, compared with the caller's expected values, or no verdict, with a reason: only transient errors, or inspectors disagree. The node signs its node outcome and sends it to the leader. A node that does not inspect at all, for example because the request is closed, refuses instead, and a refusal is not a node outcome. |
| Attempt result | The leader | What the leader decides from the node outcomes: sign when they all match, retry when a node has no verdict because of transient errors, end the request with an inconclusive when node outcomes or inspectors disagree. A refusal or a failure after agreement only causes a retry. |
| Signed outcome | The network | The answer the caller gets: success, negative verdict, or inconclusive. |

---

## Architecture

Callers talk to the contract as they do today. What changes is what the nodes sign, and when
they stop trying.

![Overview: the caller sends a V2 request with the values it expects. The contract stores the request, the hash of the expected values and the block height under a yield id it picks, and emits the id. The leader takes an asset if needed and sends Start. Everyone inspects, and followers return their signed outcome with their share. The signature over the request, its block height, the yield id and the outcome goes back to the contract, which returns the response with the signature and the outcome to the caller. When nodes disagree, or after the last attempt, the leader runs the inconclusive round with signed evidence from followers, and its signature also answers only that yield.](attachments/overview.png)

1. **Request.** The caller calls `verify_foreign_transaction_v2` with the values it expects.
   The contract picks a yield id, stores the request, the hash of the expected values and the
   current block height under it, and announces the id in an event. Every node's indexer picks
   up the request and the id together.
2. **Start.** The leader takes an asset if needed and sends Start. A node takes part only while
   the request is unanswered and inside its 200 block window.
3. **Inspect.** The leader and followers inspect in parallel. Each follower signs what it found
   and sends it to the leader, followed by its share if it found a verdict.
4. **Sign or fail.** If every node outcome matches the leader's, the shares combine into a
   signature. If nodes disagree, the request goes straight to the inconclusive. Otherwise the
   attempt fails and the leader retries.
5. **Inconclusive.** When nodes disagree, or after the last attempt fails, the leader runs one
   more round to sign an inconclusive for the request. Signers only join if the node asking is
   the request's leader and shows signed evidence from its followers.
6. **Respond.** The leader submits the yield id, the outcome and the signature. The contract
   looks up the request, rebuilds the hash, checks the signature and resumes that yield.

V1 requests are not affected by any of this.

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
    NegativeVerdict { verdict: ForeignTxVerificationNegativeVerdict },
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

- **Every response is tied to the request.** The signature covers the yield id, so it answers
  exactly one request, once. This is what makes V2 replay safe (Component 2).
- **Every response says when it was checked.** Nodes only sign within 200 blocks of
  `request_block_height` (Component 2), so the signature proves the check happened in that
  range. Someone outside NEAR can verify this from the signature alone.
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
  The inconclusive only says the nodes disagreed or ran out of attempts, so it has its own
  variant instead of being one of the negative verdicts.
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
- **On NEAR, a caller can trust the outcome.** The contract checked the signature over a
  payload that includes the caller's own expected values hash, so `Verified {}` means the
  values the caller asked for. A receiver outside NEAR knows the values, computes the hash,
  rebuilds `ForeignTxSignPayload::V2` and verifies the signature. We extend the SDK to do
  this, and document it so that callers who don't use the SDK verify it too.

### Component 2: yields and the respond method

**Yield ids.** The contract keeps a `u64` counter that only goes up and survives every
migration. For each V2 request it:

1. hashes the next counter value into an id, `sha256("verify_foreign_tx_v2" || counter)`,
2. creates the yield under that id with `promise_yield_create_with_id`,
3. stores the request, the hash of its expected values and the current block height under
   the id, and hands the id to the timeout callback.

The prefix keeps V2 ids from colliding with ids the contract may pick for other yields later,
because all yields of one account share a namespace. The create call returns `None` if a yield
with that id is still pending. That can't happen with a fresh counter value, so if it ever
does, we treat it as a bug and fail the request. The respond method resumes the yield with
`promise_yield_resume_with_yield_id`. Ids are hex encoded in the event and the response, and
all of this needs NEAR protocol version 85, which mainnet already runs.

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
requests. What is new is that a V2 signature claims the window through
`request_block_height`, so a receiver outside NEAR can rely on it.

**One signature, one request.** Identical requests made at the same time each get their own
attempt, since nodes queue them by receipt id.

### Component 3: attempts that fail fast

Today a follower that fails before signing sends nothing, and the leader waits out the
attempt deadline. A V2 attempt runs like this:

1. **Open.** The leader takes an asset if needed, whose participants are all within the
   indexer margin, and sends Start right away, without waiting for its own inspection. So
   every attempt uses up an asset, even one that fails. V1 inspects first, so that a bad
   request costs no presignature. V2 gives that up for the fastest happy path.
2. **Inspect.** Everyone inspects in parallel. A node retries transient provider errors within
   its local 5 second inspection cap.
3. **Report.** Each follower signs its node outcome and sends it to the leader: its verdict,
   followed by its share, or no verdict with the reason. A follower that doesn't inspect at
   all, because the request is closed, it hasn't indexed the request within 3 seconds, or the
   sender isn't the leader in its view, refuses with the network abort.
4. **Fail fast.** The leader ends the attempt as soon as:
   - two node outcomes differ, between two followers or between a follower and itself, or
   - a node, including leader nodes, has no node outcome: it reports no verdict, or it
     refuses.

   None of these waits for the deadline. The existing failure modes stay as they are: a share
   that doesn't combine, or a follower silent past the attempt deadline, still fails the
   attempt.

What happens next depends on why the attempt ended:

| Why the attempt ended | Next |
|---|---|
| Two followers' node outcomes differ, or a follower's inspectors disagree | The request ends with an inconclusive at once, with a metric and an alert. A disagreement is never retried. |
| A follower has no verdict because of transient errors | The leader retries. |
| Only the leader's own outcome differs, or the leader has no verdict | The leader retries. Its own outcome is never evidence (Component 4). |
| A follower refuses, goes silent, or its share fails after every node agreed | The leader retries. This is a problem within the cluster, not a finding about the transaction, so it is never evidence. |

**Signed node outcomes.** A follower signs its node outcome so that the leader can show it to
other nodes as evidence (Component 4). It signs with the Ed25519 key of its TLS identity.
Every node already knows every other node's TLS key from contract state, and the contract
only accepts a key together with a TEE attestation that commits to it.

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

A follower signs the prefix `near-mpc foreign tx v2 node outcome` followed by the Borsh
encoded statement. Refusals are not signed, as they are problems within the cluster, not
findings, so they stay the plain network abort and are never evidence for inconclusive
signing.

**Attempt deadline: 13 seconds from Start.** That is 3 seconds (5 blocks) for a follower's
indexer to pick up the request, 5 seconds for inspection, and 5 seconds for the network
communication within the cluster. V1 keeps its 60 seconds.

If no suitable asset is available, the leader waits for one before Start. The wait is outside
the attempt deadline and doesn't use up an attempt. A request that gets no asset within its
window times out.

**Indexer margin: 5 blocks.** A mainnet block takes about 0.6 seconds, so the 3 second wait
covers 5 blocks. Over a week of mainnet samples, an online node's indexer was within 5 blocks
of the most advanced one 99.94% of the time. Today an asset may include a node 50 blocks
behind the leader, and that follower would miss the wait. So the V2 leader only takes an asset
whose participants are all within 5 blocks of its own indexer.

![Attempts: matching node outcomes sign the attempt. A disagreement goes straight to the inconclusive round. A follower without a verdict because of transient errors fails the attempt with signed evidence. A refusal, a silent follower, a bad share, or a leader without a verdict or with a different outcome fails it without evidence. The leader retries while attempts remain. With evidence from every attempt, it runs the inconclusive round, and otherwise the request times out.](attachments/attempts.png)

**Retries: up to three attempts.** The leader retries at once after a failed attempt. Retries
cover only problems within the cluster and transient provider errors, because a disagreement
ends the request at once. A follower joins at most three attempts per request and leader,
which bounds the assets one leader can use up. A new leader starts its own attempts. Sign,
CKD and V1 keep their limit of ten. A transaction that isn't final yet also ends inconclusive,
and the caller asks again later. Component 4 lists how long each case takes.

### Component 4: the signed inconclusive

1. **The leader runs one more signing round**, this time over a V2 payload whose outcome is
   `Inconclusive`. The payload only depends on the request, its expected values hash, its
   block height and the yield id, so every signer derives the same hash, and the round can
   only fail if a signer doesn't show up.
2. **Signers check the leader and the evidence.** A node only signs if the sender is the
   request's leader in its own view, by the same rule the request queue uses to pick leaders,
   and the request is still open. The round's Start carries the evidence: signed node
   outcomes from followers, never the leader's own. A signer checks each against the
   follower's TLS key from contract state, and joins only if they show:
   - two follower verdicts for the same attempt that differ,
   - one follower whose inspectors disagree, or
   - one follower without a verdict because of transient errors, in each of three attempts.
3. **Up to three rounds.** Like the attempts, the inconclusive gets three tries in total, to
   ride out a flaky network. Each try has a 5 second deadline and uses a fresh asset, and a
   signer joins at most three rounds per request and leader. If all three fail, the request
   times out, as it does today.
4. **The contract resumes that yield**, and the caller gets `Inconclusive {}`.

**What it means.** The nodes disagreed about the transaction, or they could not reach an
answer within the attempt budget. To a caller both lead to the same next step, so both are
reported the same way: the network couldn't decide, and the caller may try again.
Disagreements should be monitored through metrics in case a provider is faulty or an ongoing
attack is happening.

**Why the leader needs evidence.** Without it, a malicious leader could end a request that
every node agreed on, and use up assets with inconclusive rounds. With it, a leader alone has
nothing to show unless followers really disagreed or failed. A leader working with one
malicious follower can still end a request it leads with an inconclusive, which the attacker
model accepts: such a pair can already let the request time out. It can't get a false
verdict signed, and it can't answer a request twice, because the contract accepts one
response per yield and honest nodes refuse a closed request.

**Why only the leader.** Today followers accept Start from any participant. Without the
leadership check, one malicious node could end any request before its honest leader answers.
If the leader goes offline or falls behind, the next node in the request's order takes over
with its own attempts, the same as for other requests.

**When there is no evidence.** Some failures leave nothing to show, and those requests time
out, as today:

- a follower stays silent, or refuses, in every attempt,
- the leader itself has no verdict, or disagrees with every follower, while the followers
  agree with each other.

**How long a request takes.** Times count from the leader's first Start and leave out any
wait for an asset. The worst cases assume that each attempt runs to its 13 second deadline,
1 second passes between attempts, and the inconclusive takes up to three rounds of 5 seconds.

| Scenario | How the request ends | Time to the answer | Answer |
|---|---|---|---|
| Every node reaches the same verdict | The first attempt signs | A few seconds, at most 13 | Success or negative verdict |
| A follower disconnects during an attempt | The next attempt uses an asset without it | A few seconds more | Success or negative verdict |
| Nodes, or the inspectors of one node, disagree | The first mismatch ends the attempt, then the inconclusive | At most about 28 seconds | Inconclusive |
| Provider errors outlast the retries inside each node | Three attempts end without a verdict, then the inconclusive | At most about 56 seconds | Inconclusive |
| A connected follower stays silent through all three attempts | The leader can't prove silence, so there is no inconclusive | 200 blocks, about 120 seconds | None, the request times out |
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

C leaves every V1 caller untouched, and gives V2 its own types from end to end. V2 also needs
to change many things outside of just request processing logic.

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
  the node gets the request and its `yield_id` together, without an extra lookup. Only the
  contract can write these logs, so a caller can't fake the id.

### When does the network give up?

Nodes fail to answer for two kinds of reasons: they disagree about the transaction, or
something breaks within the cluster or at a provider. Only the second kind is worth a retry.

- **A. After one failed attempt.** Gives up on requests a single retry would have completed,
  for example after a provider blip.
- **B. Retry every failure up to the budget, with the leader's word enough to end the
  request.** Retries disagreements that should end the request at once, and lets a lone
  malicious leader end any request it leads, even one every node agreed on.
- **C. End a disagreement at once, retry everything else up to three attempts, and require
  signed evidence from followers for the inconclusive (chosen).**

C follows the rule that a disagreement is final, keeps a failed request short, and stops a
lone leader from ending a request everyone agreed on. It needs signed node outcomes, which use
each node's existing TLS key.

### How does V2 roll out?

V1 stays untouched, so no upgrade order breaks existing callers.

- **The V2 method ships in its own contract release**, once every node supports V2. Until
  then, old nodes would ignore V2 requests and they would time out.
- **P2P needs one protocol version bump**, for the follower's signed node outcome as a new
  message kind, and for the inconclusive round as a new task kind. Aborts reuse the existing
  message.

---

## Security analysis

| Threat                                                 | Defense                                                                                                                                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious leader forges a verdict                      | Every follower checks the transaction itself, and shares signed over different outcomes don't combine into a signature.                                                                       |
| Leader asks to sign for a request that doesn't exist   | Honest nodes only sign for requests they have seen on chain themselves, so every honest signer checked after the request was made.                                                            |
| Old _not found_ replayed after the transaction lands   | Each signature is tied to one request, which is closed once it is answered. A new request gets its own check.                                                                                 |
| Signature replayed on another caller's request         | The signature names its yield id, and the contract only answers that yield.                                                                                                                   |
| Old _not found_ relayed off NEAR later                 | The signature carries the request's block height, and honest nodes only sign within 200 blocks of it. The receiver can see how old the answer is.                                             |
| Leader reruns an answered or expired request           | Honest nodes refuse to join once their indexer shows the request answered or older than 200 blocks.                                                                                           |
| Responder submits a signature with a different outcome | The contract rebuilds the hash from the submitted outcome, and rejects the response if the signature doesn't match.                                                                           |
| Provider details split honest nodes                    | Negative verdicts carry no provider data, so honest nodes sign the same bytes.                                                                                                                |
| Faulty provider drives a verdict                       | Blocked as long as the node's other providers answer, because they would disagree. If they are all down, the faulty provider can drive a verdict, just as it can drive a success today.       |
| Follower refuses, goes silent or sends a bad share     | Fails that attempt, and the leader retries. It is never evidence for an inconclusive, so after three attempts the request times out, as today.                                                |
| Follower signs a false node outcome                    | It can end a request whose attempt includes it, as it can make an attempt fail today. Its signature shows who did it, and it can never forge a valid threshold signature.                     |
| Malicious leader ends a request every node agreed on   | It can't, because it has no follower evidence to show. Working with one malicious follower it can, and the caller gets an inconclusive instead of today's timeout.                            |
| Malicious leader uses up assets on a request it leads  | A follower joins at most three attempts and three inconclusive rounds per request and leader.                                                                                                 |
| Leader forges or replays a follower's node outcome     | Node outcomes are signed with the follower's attested TLS key, and name the yield id, the leader and the attempt.                                                                             |
| A node that isn't the leader starts an inconclusive    | Nodes check who leads the request and refuse.                                                                                                                                                 |
| Caller plants a fake yield id                          | Nodes read the id only from the log of the MPC contract's own V2 receipt. Only the contract's code can log there, and it logs only the id it generated.                                       |
| Late timeout removes an open request                   | Each request is stored under its own yield id, and a timeout only removes its own entry.                                                                                                      |
| Node overstates its indexer height to lead more        | Not new, and leader eligibility doesn't change. Such a node can already let those requests time out. Without follower evidence it can't end them inconclusive.                                |
| Caller floods requests the network can't decide        | Every attempt and inconclusive round uses an asset. We accept that as the cost of signing every answer.                                                                                       |
| Caller trusts the outcome label                        | On NEAR the contract checked the signature over the caller's own expected values hash, so the label is safe to trust. Outside NEAR the receiver must check the signature, which the SDK does. |
| Caller states wrong expected values                    | Nodes sign the negative verdict `ValuesMismatch`. It answers only that request.                                                                                                               |

---

## Worked examples

- **One divergent node F on an honest network.** F's node outcome differs from the other
  followers', so an attempt that includes F ends the request with an inconclusive at once,
  and the alert names F. A leader whose asset excludes F succeeds at once. Today the first
  group times out.
- **Provider outage.** Each node retries its providers within the inspection cap, then
  reports no verdict. After three attempts the caller gets an inconclusive instead of a
  timeout. Each attempt uses an asset.
- **Malicious follower M.** If M signs a false node outcome, requests whose attempt includes M
  end in an inconclusive, and M's signature shows who did it. If M only refuses or stays
  silent, those requests time out, as today.
- **Malicious leader M.** M can't get an inconclusive signed alone, since it has no follower
  evidence to show. It can let a request it leads time out, as today.
- **M racing an honest leader H.** Signers refuse M, since it isn't the leader in their view,
  and H answers the request.
- **Eve steers a copy of Bob's request to a malicious leader M.** A request's leader follows
  from a hash of its receipt id, which Eve can't pick, but she can submit identical copies of
  Bob's request until one of them lands on M. What M can and cannot do with that copy:
  - **Cannot end it with an inconclusive alone.** M is the copy's leader, but signers also
    need signed evidence from followers, which M can't forge. M could already let the copy
    time out today, and still can. Only with a malicious follower in the copy's attempt can M
    end it with an inconclusive.
  - **Cannot get a false verdict signed.** Fewer nodes than the threshold are malicious, so any
    threshold of signers includes an honest node. That node signs only the outcome it derived itself, and shares over
    different hashes don't combine. M can't get a false success or a false negative verdict
    signed, for the copy or for any other request. The only way to one is the faulty provider
    case in the table, which doesn't depend on who leads.
  - **Cannot touch Bob's request.** The inconclusive names the copy's yield id, and the contract
    only answers that copy. M can't run an inconclusive round for Bob's request either, since
    signers see Bob's leader H, not M, as its leader. H answers Bob as usual.

  So steering a request to M gets Eve at most a timeout on her own copy, or a signed
  inconclusive if a malicious follower helps, which is no worse than today. Each copy costs
  her a transaction and costs the network an asset.
