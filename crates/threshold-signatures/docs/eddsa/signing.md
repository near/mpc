# EdDSA signatures

This document specifies the distributed EdDSA signing protocol called FROST.
The implementation is heavily inspired by the Zcash Foundation
[implementation](https://github.com/ZcashFoundation/frost) which builds the
scheme on top of Curve25519. The implementation thus generates signatures
that can be checked by any Ed25519 verifier.
We implement the two round FROST protocol without the extra round responsible
of detecting which party deviated from the protocol.

### Note:  We denote $\mathcal{P}$ the set of participants included the DKG and the threshold $t = \mathsf{MaxMalicious}+1$

## Signing

In this phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}$
of size $N_1 > t$ wishes to generate an EdDSA signature. Following the
[RFC9591](https://datatracker.ietf.org/doc/html/rfc9591) we will use
domain separated hash functions $H_1, H_2, H_3, H_4$.

The inputs to this phase are:

1. The secret key share $x_i$.
2. The public key $X$
3. The message $m$

### Round 1

1.1 Each $P_i$ commits to its secret share $x_i$ following the
[RFC9591](https://datatracker.ietf.org/doc/html/rfc9591#name-round-one-commitment) standards. In short, the following cryptographic steps are executed:

* Pick two $32$ bytes seeds uniformly at random $\mathit{seed}_1$ and $\mathit{seed}_2$.
* Compute the following binding and hiding nonces:

$$
\begin{aligned}
a_i &\gets H_3(\mathit{seed}_1, x_i)\cr
b_i &\gets H_3(\mathit{seed}_2, x_i)
\end{aligned}
$$

* Compute the following binding and hiding points:

$$
\begin{aligned}
A_i&\gets a_i \cdot G\cr
B_i &\gets b_i \cdot G
\end{aligned}
$$

1.2 $\star$ Each $P_i$ sends $(A_i, B_i)$ **only to the coordinator**.

#### Round 1 (Coordinator)

1.3 $\bullet$ The coordinator waits to receive $(A_j, B_j)$ from every party $P_j$.

1.4 The coordinator collects all terms into a set $\mathit{commits}\gets \set{(j, A_j, B_j)\colon \forall j \in \set{1.. N_1}}$.

1.5 $\star$ The coordinator sends $(\mathit{commits}, m)$ to every participant.

### Round 2

2.1 $\bullet$ Each $P_i$ waits to receive $(\mathit{commits}, m^*)$ sent by the coordinator.

2.2 Each $P_i$ verifies that $m = m^*$

2.3 Each $P_i$ computes a signature share using following [RFC9591](https://datatracker.ietf.org/doc/html/rfc9591#name-round-two-signature-share-g).

In short, the following cryptographic steps are executed:

* $\blacktriangle$ Assert that $(i, A_i, B_i) \in \mathit{commits}$.
* Compute the hash $h\gets H_4(m)$.
* Compute the multiple hashes for all $j\in\set{1.. N_1}$:

$$
\rho_j \gets H_1(X, h, \mathit{commits}, j)
$$

* Compute the following group commitment

$$
R\gets \sum_j (A_j+ \rho_j \cdot B_j)
$$

* Compute the following challenge:

$$
c\gets H_2(R, X, m)
$$

* Compute the following signature share:

$$
s_i = a_i + b_i * \rho_i+ \lambda(\mathcal{P}_1)_i * x_i * c
$$

2.4 Each $P_i$ sends its signature share $s_i$ **only to the coordinator**.

#### Round 2 (Coordinator)

2.5 $\bullet$ The coordinator waits to receive the signature share $s_j$ from every party $P_j$.

2.6 The coordinator runs the aggregation following [RFC9591](https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation). In short, the following sum is executed:

$$
s\gets \sum_j s_j
$$

2.7 $\blacktriangle$ The coordinator asserts that $(R, s)$ is a valid EdDSA signature for message $m$ over Ed25519.

**Output:** the signature $(R, s)$.

*Note: We do not make use of the cheater detection feature which requires additional computation and potentially and extra round of communicating the cheater to the rest of the participant.*
