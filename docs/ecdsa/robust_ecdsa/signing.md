This document specifies the signing protocol described in [[DJNPO20](https://eprint.iacr.org/2020/501)].
The protocol is split into two phases, a pre-signing phase and a signing phase.

*Note that we slightly modify the original scheme and push parts of the computation done on the signing phase to the presigning phase to improve the performance of the former phase. Additionally, we allow rerandomization and key derivation of the presignature following [[GS21](https://eprint.iacr.org/2021/1330.pdf)] and introduce a coordinator to the online signing phase to reduce the communication complexity.*

### Note:  We denote $\mathcal{P}$ the set of participants included the DKG and the threshold $t = \mathsf{MaxMalicious}$

# Presigning

In this phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}$
of size $N_1 \geq 2t +1$ wishes to generate a threshold $t' = t + 1$ sharing
of a pre-signature.

The input to this phase is:

1) The secret key share $x_i$.

**Round 1:**

1. Each $P_i$ generates two random degree $t$ polynomials $f_{k_i}$ and $f_{a_i}$
2. Each $P_i$ generates three random degree $2t$ polynomials $f_{b_i}$, $f_{d_i}$, and $f_{e_i}$ and set their constant terms to zero.
3. $\textcolor{red}{\star}$ Each $P_i$ **privately** sends
$(k_{ij}, a_{ij}, b_{ij}, d_{ij}, e_{ij})$ to every party $P_j$ such that:

$$
k_{ij} \gets f_{k_i}(j) \qquad
a_{ij} \gets f_{a_i}(j) \qquad
b_{ij} \gets f_{b_i}(j) \qquad
d_{ij} \gets f_{d_i}(j) \qquad
e_{ij} \gets f_{e_i}(j)
$$

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive $(k_{ji}, a_{ji}, b_{ji}, d_{ji}, e_{ji})$ from each other $P_j$.
2. Each $P_i$ sums the shares received from the participants:

$$
k_i \gets \sum_j k_{ji} \qquad
a_i \gets \sum_j a_{ji} \qquad
b_i \gets \sum_j b_{ji} \qquad
d_i \gets \sum_j d_{ji} \qquad
e_i \gets \sum_j e_{ji}
$$

3. Each $P_i$ computes $R_i = g^{k_i}$
4. Each $P_i$ computes $w_i = a_i \cdot k_i + b_i \quad$ ($b_i$ being a blinding factor for $a_i \cdot k_i$)
5. $\star$ Each $P_i$ sends $(R_i, w_i)$ to every party.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $(R_i, w_i)$ from each $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that:
$\forall j \in \\{t+2.. n\\},\quad \mathsf{ExponentInterpolation}(R_1, \ldots R_{t+1}; j) =  R_j$
3. Each $P_i$ computes $R \gets \mathsf{ExponentInterpolation}(R_1, \ldots R_{t+1}; 0)$
4. $\blacktriangle$ Each $P_i$ *asserts* that $R \neq Identity$
5. Each $P_i$ computes $W_i \gets R^{a_i}$
6. $\star$ Each $P_i$ sends $W_i$ to every party.
7. $\bullet$ Each $P_i$ waits to receive $W_j$ from every party.
8. $\blacktriangle$ Each $P_i$ *asserts* that:
$\forall j \in \\{t+2.. n\\},\quad \mathsf{ExponentInterpolation}(W_1, \ldots W_{t+1}; j) =  W_j$
9. Each $P_i$ computes $W \gets \mathsf{ExponentInterpolation}(W_1, \ldots W_{t+1}; 0)$
10. $\blacktriangle$ Each $P_i$ *asserts* that $W = w\cdot G$
11. Each $P_i$ performs polynomial interpolation of degree $2t$ to derive $w$ as in $w \gets \sum_i \lambda(\mathcal{P}_1)_i \cdot w_i$.
12. $\blacktriangle$ Each $P_i$ *asserts* that $w \neq 0$.
13. Each $P_i$ computes $c_i \gets a_i \cdot w^{-1}$
14. Each $P_i$ computes $\alpha_i \gets c_i+d_i$
15. Each $P_i$ computes $\beta_i \gets c_i \cdot x_i$.

**Output:** the presignature $(R, \alpha_i, \beta_i, c_i, e_i)$.

# Signing

In this phase, a set of parties $\mathcal{P}_2 \subseteq \mathcal{P}_1$
of size $N_2 > t$ wishes to generate an ECDSA signature.

The inputs to this phase are:
1) The presignature $(R, \alpha_i, \beta_i, c_i, e_i)$,
2) The public key $X$
3) A "fresh" public source of entropy $\rho$
4) A tweak $\epsilon$ used during key derivation
5) The message hash $h= H(m)$
6) The derived public key $Y = X + \epsilon \cdot G$

**Rerandomization & Key Derivation:**

1. Each $P_i$ derives a randomness $\delta \gets \mathsf{HKDF}(Y, \epsilon, h, R, \rho)$
2. Each $P_i$ rerandomizes the following elements:

    * $R  \gets R^\delta$
    * $\alpha_i \gets \alpha_i \cdot \delta^{-1}$
    * $\beta_i \gets (\beta_i + c_i \cdot \epsilon) \cdot \delta^{-1}$

**Round 1:**

1. Each $P_i$ computes its signature share $s_i \gets \alpha_i * h + \beta_i \cdot R_\mathsf{x} + e_i$ where $R_\mathsf{x}$ is the x coordinate of $R$.
2. Each $P_i$ linearizes its signature share $s_i \gets \lambda(\mathcal{P}_2)_i s_i$.
3. $\star$ Each $P_i$ sends $s_i$ **only to the coordinator**.

**Round 1 (Coordinator):**

3. $\bullet$ The coordinator waits to receive $s_j$ from every party.
4. The coordinator sums the received elements $s \gets \sum_j s_j$.
5. $\blacktriangle$ The coordinator *asserts* that $s\neq 0$
6. Perform the low-S normalization, i.e. $s \gets -s$ if $s\in\\{\frac{q}{2}..~q-1\\}$
7. $\blacktriangle$ The coordinator asserts that $(R, s)$ is a valid ECDSA signature for $h$.

**Output:** the signature $(R, s)$.

*Note that such message-signature pair is only accepted by a verifier that uses a derived public key, i.e.,* $X + \epsilon\cdot G$.

>  [click to see the Notation reference](../../network_layer.md#documentation-notation).

# Differences with [[DJNPO20](https://eprint.iacr.org/2020/501)]

Our specification introduces several modifications to the original paper, aimed at enhancing performance, security, and compatibility. The key changes are:

1. Sign phase computation optimization
2. Communication optimization
3. Presignature rerandomization
4. Outsourcing the message hash

Changes (1) and (2) improve the overall performance of the scheme, change (3) strengthens the scheme's overall security, and change (4) enhances compatibility with external systems that rely on this library for signing operations.

### Sign phase computation optimization
We optimize the signing phase in two ways:
1. We require from the sender to linearize the value $s_i$ before sending it.
This amortizes the cost of computation for the receiver by $n-1$ lagrange coefficients computation and $n-1$ scalar multiplications.
The receiver only has to sum up the received values.

2. We push part of the computation that happens in the signing phase in [[DJNPO20](https://eprint.iacr.org/2020/501)] to the presigning phase.
This is represented for instance with steps 14 and 15 in round 3 of the presigning phase.

### Communication optimization
The original paper does not consider the existence of a coordinator and treats all the participants symmetrically.
Such choice can overload the network with $O(n^2)$ messages. Instead, we make the signing phase asymmetric and require
that each of the parties would only send their shares to the coordinator which combines them in the corresponding way.

### Presignature rerandomization and key derivation
Following [[GS21](https://eprint.iacr.org/2021/1330.pdf)]'s recommendation, we rerandomize the presignature to make the Wagner attack practically infeasible.
The key derivation is a feature that allows the holder of a secret key to derive multiple secret keys for different applications (e.g. an MPC node holding a secret key share that uses to derive several clients secret key shares).
The scheme remains correct after this rerandomization and key derivation.

### Outsourcing the message hash
Providing the signing phase with raw hashes as inputs instead of the original messages is beneficial for many use cases, e.g., the signing nodes receive a hashed payload and are required to generate a signature that is valid for a "universal verifier". Note that such API is quite common in cryptographic libraries and has been intensively studied for the non-distributed case in [[PR24](https://link.springer.com/chapter/10.1007/978-3-031-57718-5_10)] and [[R25](https://www.research-collection.ethz.ch/bitstream/handle/20.500.11850/729349/uploaded-version.pdf?sequence=1)].
