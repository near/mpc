# Signed Negative and Inconclusive Outcomes for Foreign Transaction Verification

**Status:** draft for discussion · **Author:** Haiyue Chen (with Claude) · **Date:** 28 September 2026

## Summary

Today a foreign transaction request is signed only when the transaction checks out. Anything
else times out after the 200 block yield window, so a caller can't tell a failed transaction
from an MPC outage.

With this design, a V2 request gets one of three signed answers:

- **Success**, as today.
- **Negative verdict:** the transaction failed or was not found, the log index is out of
  range, the account was not found, or the block is not canonical. Signed under the same rules
  as a success.
- **Inconclusive:** the network could not reach an answer within its attempt budget. It says nothing
  about the transaction.

If the network can't sign at all, the request still times out.

In short:

- Callers opt in through a new method, `verify_foreign_transaction_v2`. V1 is unchanged.
- Every V2 answer is tied to the one request it answers. It can't be reused for any other
  request, so an old _not found_ can never answer a newer one.
- Every V2 answer also records the block the request was made in, and nodes only sign within
  200 blocks of it. Anyone who receives the signature later, even outside NEAR, can tell when
  the network checked.
- V2 attempts fail fast. Each follower sends the leader its outcome along with its share, or
  an abort if it has nothing to sign, so the leader ends a failed attempt at the first mismatch
  instead of waiting out the deadline.
- When the leader runs out of attempts, it coordinates signing for an inconclusive response
  payload. Only the request's leader can do this.

---

## Architecture

Callers talk to the contract as they do today. What changes is what the nodes sign, and when
they stop trying.

![Overview: the contract stores the V2 request and its block height under a yield id it picks, and emits the id. The leader takes a presignature and sends Start. Everyone inspects, and followers return their outcome with their share, or an abort. The signature over the request, its block height, the yield id and the outcome goes back to the contract, which resumes that yield. After the last attempt the leader runs the inconclusive round, whose signature also answers only that yield.](attachments/overview.png)

1. **Request.** The caller calls `verify_foreign_transaction_v2`. The contract picks a yield
   id, stores the request and the current block height under it, and announces the id in an
   event. Every node's indexer picks up the request and the id together.
2. **Start.** The leader takes a presignature and sends Start. A node takes part only while the
   request is unanswered and inside its 200 block window.
3. **Inspect.** The leader and followers inspect in parallel. Each follower sends the leader
   its outcome along with its share, or an abort if it has nothing to sign.
4. **Sign or fail.** If every outcome matches the leader's, the shares combine into a
   signature. Otherwise the attempt fails and the leader retries.
5. **Inconclusive.** After the last attempt fails, the leader runs one more round to sign an
   inconclusive for the request. Signers only join if the node asking is the request's leader.
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
    request_block_height: NearBlockHeight,         // the block the request's yield was created in
    yield_id: YieldId,                             // the one yield this answers
    outcome: ForeignTxVerificationOutcome,
}

enum ForeignTxVerificationOutcome {
    Verified { values: Vec<ExtractedValue> },
    NegativeVerdict(ForeignTxVerificationNegativeVerdict),
    Inconclusive,
}

enum ForeignTxVerificationNegativeVerdict {
    TransactionFailed,
    LogIndexOutOfBounds,
    TransactionNotFound,
    AccountNotFound,
    NonCanonicalBlock,
}
```

- **Every answer names its request.** The signature covers the yield id, so it answers exactly
  one request, once. This is what makes V2 replay safe (Component 2).
- **Every answer says when it was checked.** Nodes only sign within 200 blocks of
  `request_block_height` (Component 2), so the signature proves the check happened in that
  range. Someone outside NEAR can verify this from the signature alone.
- **Negative verdicts carry no extra data.** The inspector's `NonCanonicalBlock` also reports a
  height and two block hashes, but those come from whichever provider answered and differ
  between nodes during a reorg. Every node must sign the same bytes, so we drop them.
- **Provider errors never become verdicts.** A node whose providers give no verdict, or
  disagree, fails the attempt instead.
- **The inconclusive is not a verdict.** A verdict is a fact about the foreign chain. The
  inconclusive only says the network ran out of attempts, so it has its own variant instead of
  being one of the negative verdicts.

```rust
struct VerifyForeignTransactionRequestV2 {
    request: ForeignChainRpcRequest,
    domain_id: DomainId,
}

struct VerifyForeignTransactionResponseV2 {
    payload_hash: Hash256,
    signature: SignatureResponse,
    request_block_height: NearBlockHeight,
    yield_id: YieldId,
    outcome: ForeignTxVerificationResponseOutcome,
}

enum ForeignTxVerificationResponseOutcome {
    Verified {},
    NegativeVerdict { verdict: ForeignTxVerificationNegativeVerdict },
    Inconclusive {},
}
```

- **No values in the response.** The resume payload is size limited, so `Verified` drops the
  values, as V1 does.
- **Callers must verify the signature.** A V2 request has no expected hash, because the hash
  covers the yield id, which the contract picks. The caller rebuilds `ForeignTxSignPayload::V2`
  from its request, the returned block height, yield id and outcome, filling in the values it
  expects for `Verified`, and verifies the signature. We extend the SDK to do this, and document
  it so that callers who don't use the SDK verify it too.

### Component 2: yields and the respond method

**Yield ids.** The contract keeps a `u64` counter that only goes up and survives every
migration. For each V2 request it:

1. hashes the next counter value into an id, `sha256("verify_foreign_tx_v2" || counter)`,
2. creates the yield under that id with `promise_yield_create_with_id`,
3. stores the request and the current block height under the id, and hands the id to the
   timeout callback.

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
    outcome: ForeignTxVerificationOutcome,       // with the values, for the hash
    signature: SignatureResponse,
)
```

The method:

1. Looks up the request stored under `yield_id`, and fails with `RequestNotFound` if there is
   none.
2. Rebuilds the payload hash from the stored request and block height, the yield id and the
   outcome.
3. Verifies the signature with the key of the request's `domain_id`.
4. Resumes that yield with a `VerifyForeignTransactionResponseV2`, values dropped, and removes
   the entry.

**This stops replay.** In V1, one signed response answers every pending request with the same
arguments. That is fine for a success, but wrong for _not found_ once the transaction lands. A
V2 signature names a single yield, which is removed as soon as it is answered, so the signature
can't be used again.

**Honest nodes only sign while the request is open.** A node only inspects requests it has
indexed itself. It also refuses to join once its own indexer shows the request answered or more
than 200 blocks old, the same expiry the leader's queue uses today. So every honest signer
really checked inside the window the signature claims, and nobody can get another signature
for a request once it is closed.

- **The contract derives the hash**, so the outcome a caller reads is exactly what was signed.
  The node doesn't resend the request either, since the contract already stores it.
- **Each request is removed exactly once.** Whichever comes first, the response or the
  timeout, removes it, and each only removes its own id.
- **One signature, one request.** Identical requests made at the same time each get their own
  attempt. Nodes already queue them separately, since each has its own receipt id.
- **V1 is untouched**, including V1 yields in flight during the upgrade.

### Component 3: attempts that fail fast

Today a follower that fails before signing sends nothing, and the leader waits out the
attempt deadline. A V2 attempt runs like this:

1. **Open.** The leader takes a presignature and sends Start right away, without waiting for
   its own inspection. So every attempt uses up a presignature, even one that fails.
2. **Inspect.** Everyone inspects in parallel.
3. **Report.** Each follower sends the leader its outcome along with its share. A follower with
   nothing to sign, because it has no verdict, hasn't indexed the request within 3 seconds, or
   sees it answered or expired, sends an abort message instead.
4. **Fail fast.** The leader ends the attempt as soon as it:
   - receives an abort from a follower,
   - sees the first two reported outcomes that don't match, between two followers or between a
     follower and itself, or
   - fails to reach a verdict itself.

   None of these waits for the deadline. The existing failure modes stay as they are: a share
   that doesn't combine, or a follower silent past the attempt deadline, still fails the
   attempt.

**We set the attempt deadline to 10 seconds**, counted from Start. It covers up to 3 seconds for a
follower's indexer to pick up the request, the 5 second inspection cap, and 2 seconds for the
network. We give V2 its own constant, and V1 keeps its 60 seconds. With three attempts, a request
whose followers keep going silent still ends well inside the 200 block yield window.

**Why the reported outcome needs no signature.** A follower tells the leader what it found so
the leader can stop a failing attempt early and log which node disagreed. The connection
between the two nodes already proves who sent it, and nobody but the leader ever reads it. A
follower that lies about its outcome can only make the attempt end sooner, which it could do
anyway by aborting. Whether an attempt succeeds is still decided by the signature alone, and
the reported outcomes are never used as evidence for an inconclusive outcome.

![Attempts: matching outcomes and shares sign the attempt. An abort, a different outcome, a bad share, a silent follower or a missing leader verdict fails it. The leader retries while attempts remain, then runs the inconclusive round up to three times, and if every round fails the request times out.](attachments/attempts.png)

**Retries.** The leader retries as soon as an attempt fails, with a budget of three attempts
in total. We give V2 its own constant, while sign, CKD and V1 keep the shared limit of ten. Every
failure counts, the leader's own included. If the leader changes, the new leader starts its
own attempts. Failures are fast, so the budget can run out within half a minute. If the
problem would clear up later, for example a transaction that isn't final yet, the request
still ends inconclusive, and the caller can simply ask again.

V1 attempts are unchanged.

### Component 4: the signed inconclusive

1. **The leader runs one more signing round**, this time over a V2 payload whose outcome is
   `Inconclusive`. The payload only depends on the request, its block height and the yield id,
   so every signer derives the same hash, and the round can only fail if a signer doesn't show
   up.
2. **Signers check the leader.** A node only signs if the sender is the request's leader in its
   own view, and the request is still open.
3. **Up to three rounds.** Like the attempts, the inconclusive gets three tries in total, to
   ride out a flaky network. Each try uses a fresh presignature. If all three fail, the request
   times out, as it does today.
4. **The contract resumes that yield**, and the caller gets `Inconclusive {}`.

**What it means.** The leader ran out of attempts. To a caller, "the nodes disagreed" and
"something broke" lead to the same next step, so both are reported the same way: the network
couldn't decide, and the caller may try again.

**Why only the leader.** Today followers accept Start from any participant. Without the
leadership check, one malicious node could end any request before its honest leader answers.
With it, a malicious node can end only the requests it leads, and it can already let those
time out.

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

C leaves every V1 caller untouched, byte for byte, and gives V2 its own types from end to end.

### How is a V2 answer kept from answering the wrong request?

A _not found_ must never answer an identical request made after the network checked.

- **A. Sign a verification height and answer every request made before it.** One signature
  can answer identical requests, but the leader has to propose the height in Start, every
  follower has to check it against its own indexer, and the contract has to track creation
  heights.
- **B. Sign the yield id (chosen).** One signature answers one request.

B needs no agreement between nodes at all, since the id comes straight from the chain.

### How does a relayed answer say when it was checked?

A negative verdict can stop being true, so a signature relayed off NEAR has to say when the
network checked.

- **A. No time in the payload.** Fine through the NEAR callback, which runs inside the yield
  window, but a relayed _not found_ would look valid forever.
- **B. A verification height agreed per attempt.** Precise to about 20 blocks, but the leader
  has to propose it in Start and every follower has to check it against its own indexer.
- **C. The request's block height, and signing only while the request is open (chosen).**
  Every node already knows the height from the block it indexed the request in, and the 200
  block window bounds the rest.

C gives a relayed signature a clear time range without adding anything to Start.

### Why is _not found_ a verdict?

It is the network's answer when it checked, after the request was made. A later check may
give a different answer, but that doesn't make the first one untrue. In addition, a caller that
submits a wrong transaction hash should get an answer, not a timeout.

### When does the network give up?

A retry can succeed when a provider blip clears, but rarely after the first few: consecutive
attempts of one leader usually have the same members, so a persistent cause fails them all.

- **A. After one failed attempt.** Gives up on requests a single retry would have completed.
- **B. Only on disagreement proven with signed evidence.** Needs signed statements and a key
  to sign them. Callers can't tell disagreement from failure anyway, and a leader can fail its
  own attempts, so the evidence protects nothing.
- **C. After the leader's budget of three attempts, with every failure counting (chosen).**

C needs only a leadership check, and keeps a failed request short.

### How do nodes and the contract agree on the yield id?

Every V2 answer is bound to one request's yield id, so nodes and the contract must agree on
that id.

- **A. Name the yield in the respond call, outside the signature.** Anyone could reuse the
  signature for another caller's request.
- **B. Sign the runtime's own yield identifier.** Works on any protocol version, but the
  timeout callback is created before the identifier exists, so a timeout could still remove
  the wrong request.
- **C. Nodes recompute the id.** Nodes would have to replay the contract's counter exactly,
  which breaks the first time a node restarts from a snapshot.
- **D. Nodes look the id up with a view call.** Adds an RPC call per request, and races with
  the block the node just indexed.
- **E. The contract picks the id, emits it as an event, and the network signs it (chosen).**
  Needs protocol version 85. Mainnet already runs version 86.

E keeps the id under the contract's control and costs nodes nothing extra, because they
already read the receipt it arrives in.

### How does V2 roll out?

V1 stays untouched, so no upgrade order breaks existing callers.

- **The V2 method ships in its own contract release**, once every node supports V2. Until
  then, old nodes would ignore V2 requests and they would time out.
- **P2P needs one protocol version bump**, for the follower's outcome and for the inconclusive
  round as a new task kind. Aborts reuse the existing message.

---

## Security analysis

| Threat                                                 | Defense                                                                                                                                                                                 |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious leader forges a verdict                      | Every follower checks the transaction itself, and shares signed over different outcomes don't combine into a signature.                                                                 |
| Leader asks to sign for a request that doesn't exist   | Honest nodes only sign for requests they have seen on chain themselves, so every honest signer checked after the request was made.                                                      |
| Old _not found_ replayed after the transaction lands   | Each signature is tied to one request, which is closed once it is answered. A new request gets its own check.                                                                           |
| Signature replayed on another caller's request         | The signature names its yield id, and the contract only answers that yield.                                                                                                             |
| Old _not found_ relayed off NEAR later                 | The signature carries the request's block height, and honest nodes only sign within 200 blocks of it. The receiver can see how old the answer is.                                       |
| Leader reruns an answered or expired request           | Honest nodes refuse to join once their indexer shows the request answered or older than 200 blocks.                                                                                     |
| Responder submits a signature with a different outcome | The contract rebuilds the hash from the submitted outcome, and rejects the response if the signature doesn't match.                                                                     |
| Provider details split honest nodes                    | Negative verdicts carry no provider data, so honest nodes sign the same bytes.                                                                                                          |
| Faulty provider drives a verdict                       | Blocked as long as the node's other providers answer, because they would disagree. If they are all down, the faulty provider can drive a verdict, just as it can drive a success today. |
| Follower aborts, goes silent or sends a bad share      | Fails that attempt, same as today. The per attempt timeout caps how long we wait for a stalling node.                                                                                   |
| Follower reports a false outcome                       | At worst it ends the attempt early or hides who diverged, which an abort can already do. It can never forge a valid signature.                                                          |
| Malicious leader ends a request it leads               | It can, and the caller gets an inconclusive instead of today's timeout.                                                                                                                 |
| A node that isn't the leader starts an inconclusive    | Nodes check who leads the request and refuse.                                                                                                                                           |
| Caller plants a fake yield id                          | Nodes read the id only from the log of the MPC contract's own V2 receipt. Only the contract's code can log there, and it logs only the id it generated.                                 |
| Late timeout removes an open request                   | Each request is stored under its own yield id, and a timeout only removes its own entry.                                                                                                |
| Node overstates its indexer height to lead more        | Not new, and leader eligibility doesn't change. Such a node can already let those requests time out, and now they end inconclusive instead.                                             |
| Caller floods requests the network can't decide        | Every attempt and inconclusive round uses a presignature. We accept that as the cost of signing every answer.                                                                           |
| Caller trusts the outcome label                        | The SDK checks the signature. Callers that don't use the SDK must check it themselves.                                                                                                  |

---

## Worked examples

- **One divergent node F on an honest network.** Attempts that include F fail, and the leader
  records that F diverged. A leader whose batch includes F ends its requests in an
  inconclusive. A leader whose batch excludes F succeeds at once. Today the first group times
  out.
- **Provider outage.** Every attempt fails fast, and the caller gets an inconclusive instead
  of a timeout. Each attempt uses a presignature.
- **Malicious follower M.** M fails every attempt it is part of. Requests whose leader's batch
  includes M end in an inconclusive instead of a timeout.
- **Malicious leader M.** M can skip its attempts and get an inconclusive signed at once for a
  request it leads. Today it can let that request time out.
- **M racing an honest leader H.** Signers refuse M, since it isn't the leader in their view,
  and H answers the request.
- **Eve steers a copy of Bob's request to a malicious leader M.** A request's leader follows
  from a hash of its receipt id, which Eve can't pick, but she can submit identical copies of
  Bob's request until one of them lands on M. What M can and cannot do with that copy:
  - **Can end it with an inconclusive.** M is the copy's leader, so signers accept its
    inconclusive round. M could already let the copy time out today. Now it ends with a signed
    "the network could not decide" instead.
  - **Cannot get a false verdict signed.** At most 7 nodes are malicious, so any 8 signers
    include an honest node. That node signs only the outcome it derived itself, and shares over
    different hashes don't combine. M can't get a false success or a false negative verdict
    signed, for the copy or for any other request. The only way to one is the faulty provider
    case in the table, which doesn't depend on who leads.
  - **Cannot touch Bob's request.** The inconclusive names the copy's yield id, and the contract
    only answers that copy. M can't run an inconclusive round for Bob's request either, since
    signers see Bob's leader H, not M, as its leader. H answers Bob as usual.

  So steering a request to M gets Eve at most a signed inconclusive on her own copy, which is
  no worse than the timeout she can get today. Each copy costs her a transaction and costs the
  network a presignature.
