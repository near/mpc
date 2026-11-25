This document specifies a batched oblivious transfer based on the
DDH dual-mode cryptosystem of [[PVW08]](https://eprint.iacr.org/2007/348), in
*messy mode*. It is a base OT meant to seed an OT extension.

$\mathbb{G}$ is a group of prime order $q$, written additively.
$\mathsf{HashToCurve}$ is a hash to $\mathbb{G}$ whose outputs have unknown
discrete logarithms.
$\mathsf{DST}$ is a domain separation tag that only this protocol uses.
A receiver $\mathcal{R}$ and a sender $\mathcal{S}$ wish to run $\ell$ oblivious
transfers.

The inputs to this protocol are:

1) The session identifier $\mathsf{sid}$, shared by both parties.
2) The choice bits $b_ 1, \ldots, b_ \ell$, held by $\mathcal{R}$ only.
3) The messages $M_ {i, 0}, M_ {i, 1} \in \mathbb{G}$ for $i \in [\ell]$, held by $\mathcal{S}$ only.

The signing algorithm provides $\mathsf{sid}$ as an input to this protocol.
It extracts $\mathsf{sid}$ from the master public key of the signing session.

# Protocol

The protocol runs $\ell$ instances of the PVW08 base OT, one for each $i \in [\ell]$.
All instances share the common reference string and the two rounds.
A failed assertion aborts the protocol.

**Common Reference String:**

Each party derives the four points from four distinct inputs:

$$
(G_ 0, H_ 0, G_ 1, H_ 1) \gets \left(\mathsf{HashToCurve}_ {\mathsf{DST}}(\mathsf{sid}, \mathcal{S}, \mathcal{R}, j)\right)_ {j \in \\\{0, 1, 2, 3\\\}}
$$

The hash takes the identities of the two parties as the ordered pair $(\mathcal{S}, \mathcal{R})$.
The tuple $(\mathsf{sid}, \mathcal{S}, \mathcal{R}, j)$ is encoded injectively.

**Round 1 (Receiver):**

1.1 For $i \in [\ell]$, sample $r_ i \overset{R}{\longleftarrow} \mathbb{F}_ q$.

1.2 For $i \in [\ell]$, compute:

$$
P_ i \gets r_ i \cdot G_ {b_ i} \qquad
Q_ i \gets r_ i \cdot H_ {b_ i}
$$

1.3 $\star$ send $(P_ i, Q_ i)_ {i \in [\ell]}$ to $\mathcal{S}$.

**Round 1 (Sender):**

1.4 $\bullet$ wait to receive $(P_ i, Q_ i)_ {i \in [\ell]}$ from $\mathcal{R}$.

1.5 $\blacktriangle$ *assert* that $\forall i \in [\ell],\quad P_ i \neq Identity$ and $Q_ i \neq Identity$.

1.6 For $i \in [\ell]$ and $b \in \\\{0, 1\\\}$, sample fresh $s_ {i, b}, t_ {i, b} \overset{R}{\longleftarrow} \mathbb{F}_ q$ and compute:

$$
U_ {i, b} \gets s_ {i, b} \cdot G_ b + t_ {i, b} \cdot H_ b \qquad
V_ {i, b} \gets s_ {i, b} \cdot P_ i + t_ {i, b} \cdot Q_ i
$$

1.7 For $i \in [\ell]$ and $b \in \\\{0, 1\\\}$, compute $W_ {i, b} \gets V_ {i, b} + M_ {i, b}$.

1.8 $\star$ send $(U_ {i, 0}, W_ {i, 0}, U_ {i, 1}, W_ {i, 1})_ {i \in [\ell]}$ to $\mathcal{R}$.

**Round 2 (Receiver):**

2.1 $\bullet$ wait to receive $(U_ {i, 0}, W_ {i, 0}, U_ {i, 1}, W_ {i, 1})_ {i \in [\ell]}$ from $\mathcal{S}$.

2.2 For $i \in [\ell]$, compute $M_ {i, b_ i} \gets W_ {i, b_ i} - r_ i \cdot U_ {i, b_ i}$.

**Output:** $\mathcal{R}$ outputs the messages $(M_ {i, b_ i})_ {i \in [\ell]}$.

*The protocol is correct because* $V_ {i, b_ i} = r_ i \cdot U_ {i, b_ i}$, so an
honest run outputs $M_ {i, b_ i}$.

>  [click to see the Notation reference](../network-layer.md#documentation-notation).

# Rationale

**Messy mode.** Write $H_ 0 = x_ 0 \cdot G_ 0$ and $H_ 1 = x_ 1 \cdot G_ 1$.
The string is in messy mode when $x_ 0 \neq x_ 1$.
Then every pair $(P_ i, Q_ i)$ other than the identity hides at least one of the
two messages, even from an unbounded receiver.
The choice bits are hidden from the sender under DDH.
The other mode of PVW08 is decryption mode, where $x_ 0 = x_ 1$.
It hides the choice bits statistically and the messages only under DDH.
Hashing cannot produce such a string, so it would need a trusted setup.

**Hashed common reference string.** A party who knew $x_ 0, x_ 1$ could cheat:
the receiver by setting $x_ 0 = x_ 1$ to learn both messages, the sender by
recovering the choice bits.
Hashing gives four points of unknown discrete logarithms, with no extra round
and no trusted setup.
The string is then in messy mode, except with probability $1/q$.
The four inputs must be distinct: equal inputs give $x_ 0 = x_ 1$.

**Hash inputs.** The ordered pair $(\mathcal{S}, \mathcal{R})$ gives each pair
of parties and each direction its own string.
$\mathsf{sid}$ binds the string to the master public key.
The pair reuses the string across runs under that key, which PVW08 allows.

**Identity check.** The pair $(0, 0)$ gives $V_ {i, 0} = V_ {i, 1} = 0$, which
sends both messages in the clear, so the sender rejects it in round 1.

# Security model

The protocol follows PVW08, which proves universally composable security
against a static malicious adversary.
The adversary corrupts the sender or the receiver.
The two parties talk over an authenticated channel.
The messages are hidden statistically.
The choice bits are hidden under DDH in $\mathbb{G}$.

**Programmable random oracle.** PVW08 works in the common reference string model.
Here $\mathsf{HashToCurve}$ replaces the trusted setup, so it is modeled as a
programmable random oracle.
The simulator needs a trapdoor of the string, which only programming gives.
Against a corrupt receiver it programs a messy string with known $x_ 0, x_ 1$
and extracts each $b_ i$.
Against a corrupt sender it programs a decryption-mode string with known
$\log_ {G_ 0} G_ 1$ and extracts both messages.
DDH makes the two strings indistinguishable.
