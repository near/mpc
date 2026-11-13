This document specifies a batched random oblivious transfer based on the
DDH dual-mode cryptosystem of [[PVW08]](https://eprint.iacr.org/2007/348), in
*messy mode*. It is a base OT meant to seed an OT extension.

$\mathbb{G}$ is a group of prime order $q$, written additively.
The receiver $\mathcal{R}$ has choice bits $b_ 1, \ldots, b_ l$.
For each $i \in [l]$ the sender $\mathcal{S}$ gets two random $\lambda$-bit keys
$k_ i^0, k_ i^1$ and $\mathcal{R}$ gets $k_ i^{b_ i}$.
Both parties share a session identifier $\mathsf{sid}$, unique to the run.

# Protocol

Protocol `PVW08-Batch-Random-OT`:

1. Both parties derive the common reference string $(G_ 0, H_ 0, G_ 1, H_ 1) \in \mathbb{G}^4$ by hashing $\mathsf{sid}$ to the curve four times.
2. For $i \in [l]$, $\mathcal{R}$ samples $r_ i \xleftarrow{R} \mathbb{F}_ q$, and sets $P_ i \gets r_ i \cdot G_ {b_ i}$ and $Q_ i \gets r_ i \cdot H_ {b_ i}$.
3. $\star$ $\mathcal{R}$ sends $(P_ i, Q_ i)_ {i \in [l]}$ to $\mathcal{S}$ in a single message.
4. $\bullet$ $\mathcal{S}$ waits to receive $(P_ i, Q_ i)_ {i \in [l]}$, and aborts unless it holds $l$ pairs and no point is the identity.
5. For $i \in [l]$ and $b \in \\\{0, 1\\\}$, $\mathcal{S}$ samples $s, t \xleftarrow{R} \mathbb{F}_ q$, and sets $U_ i^b \gets s \cdot G_ b + t \cdot H_ b$ and $V_ i^b \gets s \cdot P_ i + t \cdot Q_ i$.
6. $\mathcal{S}$ computes $k_ i^b \gets H_ {(\mathsf{sid}, i, b, P_ i, Q_ i, U_ i^b)}(V_ i^b)$.
7. $\star$ $\mathcal{S}$ sends $(U_ i^0, U_ i^1)_ {i \in [l]}$ to $\mathcal{R}$ in a single message.
8. $\bullet$ $\mathcal{R}$ waits to receive $(U_ i^0, U_ i^1)_ {i \in [l]}$.
9. For $i \in [l]$, $\mathcal{R}$ computes $k_ i^{b_ i} \gets H_ {(\mathsf{sid}, i, b_ i, P_ i, Q_ i, U_ i^{b_ i})}(r_ i \cdot U_ i^{b_ i})$.

Here $H$ is a hash function providing a key derivation function
$\mathbb{G} \to \mathbb{F}_ 2^\lambda$.
The protocol is correct because $V_ i^{b_ i} = r_ i \cdot U_ i^{b_ i}$.

# Choices

**Messy mode.** Write $H_ 0 = x_ 0 \cdot G_ 0$ and $H_ 1 = x_ 1 \cdot G_ 1$.
The string is in messy mode when $x_ 0 \neq x_ 1$.
Then every pair $(P_ i, Q_ i)$ other than the identity is inconsistent with at
least one branch $b$, and on that branch $V_ i^b$ is uniform given $U_ i^b$: the
key is hidden even from an unbounded receiver.
The choice bits are hidden from the sender under DDH.

**Hashed common reference string.** A party who chose the string could cheat:
the receiver by picking $x_ 0 = x_ 1$ and learning both keys, the sender by
using $x_ 0, x_ 1$ to recover the choice bits.
Hashing $\mathsf{sid}$ to the curve gives four points whose discrete logarithms
nobody knows, in messy mode except with probability $1/q$, with no extra round
and no trusted setup.

**Random OT.** The parties hash $V_ i^b$ into a key in place of encrypting a
message with it, as the paper does. This is what an OT extension consumes, and
it halves the sender's message.

**One string per batch, fresh randomness per transfer.** The whole batch shares
the string and takes one message in each direction.
The sender's $(s, t)$ is sampled independently for every $i$ and $b$: sharing
it across the batch would make the hidden values $V_ i^b$ dependent on one
another.

**Identity check.** The pair $(0, 0)$ is consistent with both branches and
gives $V_ i^0 = V_ i^1 = 0$, so step 4 must reject it.
