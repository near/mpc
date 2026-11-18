This document specifies a batched oblivious transfer based on the
DDH dual-mode cryptosystem of [[PVW08]](https://eprint.iacr.org/2007/348), in
*messy mode*. It is a base OT meant to seed an OT extension.

$\mathbb{G}$ is a group of prime order $q$, written additively.
A receiver $\mathcal{R}$ and a sender $\mathcal{S}$ wish to run $l$ oblivious
transfers.

The inputs to this protocol are:

1) The session identifier $\mathsf{sid}$, shared by both parties and unique to the run.
2) The choice bits $b_ 1, \ldots, b_ l$, held by $\mathcal{R}$ only.
3) The messages $M_ i^0, M_ i^1 \in \mathbb{G}$ for $i \in [l]$, held by $\mathcal{S}$ only.

# Protocol

**Common Reference String:**

1. Each party derives $(G_ 0, H_ 0, G_ 1, H_ 1) \in \mathbb{G}^4$ by hashing $\mathsf{sid}$ to the curve four times.

**Round 1 (Receiver):**

1. For $i \in [l]$, $\mathcal{R}$ samples $r_ i \xleftarrow{R} \mathbb{F}_ q$.
2. For $i \in [l]$, $\mathcal{R}$ computes:

$$
P_ i \gets r_ i \cdot G_ {b_ i} \qquad
Q_ i \gets r_ i \cdot H_ {b_ i}
$$

3. $\star$ $\mathcal{R}$ sends $(P_ i, Q_ i)_ {i \in [l]}$ to $\mathcal{S}$.

**Round 1 (Sender):**

1. $\bullet$ $\mathcal{S}$ waits to receive $(P_ i, Q_ i)_ {i \in [l]}$ from $\mathcal{R}$.
2. $\blacktriangle$ $\mathcal{S}$ *asserts* that it holds $l$ pairs.
3. $\blacktriangle$ $\mathcal{S}$ *asserts* that $\forall i \in [l],\quad P_ i \neq Identity$ and $Q_ i \neq Identity$.
4. For $i \in [l]$ and $b \in \\\{0, 1\\\}$, $\mathcal{S}$ samples fresh $s, t \xleftarrow{R} \mathbb{F}_ q$ and computes:

$$
U_ i^b \gets s \cdot G_ b + t \cdot H_ b \qquad
V_ i^b \gets s \cdot P_ i + t \cdot Q_ i
$$

5. For $i \in [l]$ and $b \in \\\{0, 1\\\}$, $\mathcal{S}$ computes $W_ i^b \gets V_ i^b + M_ i^b$.
6. $\star$ $\mathcal{S}$ sends $(U_ i^0, W_ i^0, U_ i^1, W_ i^1)_ {i \in [l]}$ to $\mathcal{R}$.

**Round 2 (Receiver):**

1. $\bullet$ $\mathcal{R}$ waits to receive $(U_ i^0, W_ i^0, U_ i^1, W_ i^1)_ {i \in [l]}$ from $\mathcal{S}$.
2. For $i \in [l]$, $\mathcal{R}$ computes $M_ i^{b_ i} \gets W_ i^{b_ i} - r_ i \cdot U_ i^{b_ i}$.

**Output:** $\mathcal{R}$ outputs the messages $(M_ i^{b_ i})_ {i \in [l]}$.

*The protocol is correct because* $V_ i^{b_ i} = r_ i \cdot U_ i^{b_ i}$.

>  [click to see the Notation reference](../network-layer.md#documentation-notation).

# Choices

**Messy mode.** Write $H_ 0 = x_ 0 \cdot G_ 0$ and $H_ 1 = x_ 1 \cdot G_ 1$.
The string is in messy mode when $x_ 0 \neq x_ 1$.
Then every pair $(P_ i, Q_ i)$ other than the identity is inconsistent with at
least one branch $b$, and on that branch $V_ i^b$ is uniform given $U_ i^b$: the
message $M_ i^b$ is hidden even from an unbounded receiver.
The choice bits are hidden from the sender under DDH.

**Hashed common reference string.** A party who chose the string could cheat:
the receiver by picking $x_ 0 = x_ 1$ and learning both messages, the sender by
using $x_ 0, x_ 1$ to recover the choice bits.
Hashing $\mathsf{sid}$ to the curve gives four points whose discrete logarithms
nobody knows, in messy mode except with probability $1/q$, with no extra round
and no trusted setup.

**Messages as inputs.** The sender's messages are inputs, as in the paper, and
each is encrypted with $V_ i^b$.
Hashing $V_ i^b$ straight into a key would halve the sender's message, but the
paper's proof does not cover it.
To seed an OT extension the caller samples the messages uniformly from
$\mathbb{G}$ and derives the $\lambda$-bit keys from them outside this protocol.

**One string per batch, fresh randomness per transfer.** The whole batch shares
the string and takes one message in each direction.
The sender's $(s, t)$ is sampled independently for every $i$ and $b$: sharing
it across the batch would make the hidden values $V_ i^b$ dependent on one
another.

**Identity check.** The pair $(0, 0)$ is consistent with both branches and
gives $V_ i^0 = V_ i^1 = 0$, which sends both messages in the clear, so the sender must reject it in round 1.
