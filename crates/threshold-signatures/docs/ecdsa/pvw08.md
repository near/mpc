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

Each party derives the four points from four distinct inputs:

$$
(G_ 0, H_ 0, G_ 1, H_ 1) \gets \left(\mathsf{HashToCurve}_ {\mathsf{DST}}(\mathsf{sid}, \mathcal{S}, \mathcal{R}, j)\right)_ {j \in \\\{0, 1, 2, 3\\\}}
$$

Here $\mathsf{HashToCurve}$ is a hash to $\mathbb{G}$ whose outputs have unknown
discrete logarithms, and $\mathsf{DST}$ is a domain separation tag that only
this protocol uses.
The hash takes the identities of the two parties as the ordered pair $(\mathcal{S}, \mathcal{R})$.

**Round 1 (Receiver):**

1.1 For $i \in [l]$, $\mathcal{R}$ samples $r_ i \overset{R}{\longleftarrow} \mathbb{F}_ q$.

1.2 For $i \in [l]$, $\mathcal{R}$ computes:

$$
P_ i \gets r_ i \cdot G_ {b_ i} \qquad
Q_ i \gets r_ i \cdot H_ {b_ i}
$$

1.3 $\star$ $\mathcal{R}$ sends $(P_ i, Q_ i)_ {i \in [l]}$ to $\mathcal{S}$.

**Round 1 (Sender):**

1.4 $\bullet$ $\mathcal{S}$ waits to receive $(P_ i, Q_ i)_ {i \in [l]}$ from $\mathcal{R}$.

1.5 $\blacktriangle$ $\mathcal{S}$ *asserts* that it holds $l$ pairs.

1.6 $\blacktriangle$ $\mathcal{S}$ *asserts* that $\forall i \in [l],\quad P_ i \neq Identity$ and $Q_ i \neq Identity$.

1.7 For $i \in [l]$ and $b \in \\\{0, 1\\\}$, $\mathcal{S}$ samples fresh $s, t \overset{R}{\longleftarrow} \mathbb{F}_ q$ and computes:

$$
U_ i^b \gets s \cdot G_ b + t \cdot H_ b \qquad
V_ i^b \gets s \cdot P_ i + t \cdot Q_ i
$$

1.8 For $i \in [l]$ and $b \in \\\{0, 1\\\}$, $\mathcal{S}$ computes $W_ i^b \gets V_ i^b + M_ i^b$.

1.9 $\star$ $\mathcal{S}$ sends $(U_ i^0, W_ i^0, U_ i^1, W_ i^1)_ {i \in [l]}$ to $\mathcal{R}$.

**Round 2 (Receiver):**

2.1 $\bullet$ $\mathcal{R}$ waits to receive $(U_ i^0, W_ i^0, U_ i^1, W_ i^1)_ {i \in [l]}$ from $\mathcal{S}$.

2.2 $\blacktriangle$ $\mathcal{R}$ *asserts* that it holds $l$ quadruples.

2.3 For $i \in [l]$, $\mathcal{R}$ computes $M_ i^{b_ i} \gets W_ i^{b_ i} - r_ i \cdot U_ i^{b_ i}$.

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
Hashing $\mathsf{sid}$ and the pair $(\mathcal{S}, \mathcal{R})$ to the curve gives four points whose discrete logarithms
nobody knows, in messy mode except with probability $1/q$, with no extra round
and no trusted setup.
This relies on the four inputs being distinct and on the tag being used nowhere
else: it is what makes $x_ 0$ and $x_ 1$ independent and uniform.
Hashing the same input four times would give $G_ 0 = H_ 0 = G_ 1 = H_ 1$, so
$x_ 0 = x_ 1$, and the receiver would learn both messages.

**Party pair in the hash.** Several pairs of parties may run this protocol
under the same $\mathsf{sid}$.
Hashing the ordered pair $(\mathcal{S}, \mathcal{R})$ gives every pair its own
string, and gives the two directions between the same parties different strings.
A transcript from one pair or one direction is then of no use in another.

**Tag and encoding.** $\mathsf{DST}$ names this protocol, its version and the
ciphersuite, meaning the group and its hash-to-curve suite.
The same $\mathsf{sid}$ then gives unrelated strings on another group or in
another version.
The tuple $(\mathsf{sid}, \mathcal{S}, \mathcal{R}, j)$ is encoded injectively:
every field has a fixed width or is prefixed by its length.
Otherwise two different tuples could hash the same bytes and share a string.

**Messages as inputs.** The sender's messages are inputs, as in the paper, and
each is encrypted with $V_ i^b$.
Hashing $V_ i^b$ straight into a key would halve what the sender sends in
round 1, as it would no longer send $W_ i^b$, but the paper's proof does not
cover it.

**One string per batch, fresh randomness per transfer.** The whole batch shares
the string and takes one message in each direction.
The sender's $(s, t)$ is sampled independently for every $i$ and $b$, and
neither is optional.
Reusing $(s, t)$ across $b$ gives $V_ i^0 = V_ i^1$, so the receiver learns both
messages: it decrypts $M_ i^{b_ i}$ and gets the other one from
$W_ i^0 - W_ i^1 = M_ i^0 - M_ i^1$.
Reusing it across $i$ makes the hidden values $V_ i^b$ linearly related.

**Identity check.** The pair $(0, 0)$ is consistent with both branches and
gives $V_ i^0 = V_ i^1 = 0$, which sends both messages in the clear, so the sender must reject it in round 1.
