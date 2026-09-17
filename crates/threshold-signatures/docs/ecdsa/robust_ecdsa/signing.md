This document specifies the signing protocol described in [[DJNPO20](https://eprint.iacr.org/2020/501)].

**We deviate from the original scheme in the following ways.** The protocol is a single four-round protocol whose inputs include the message hash and the tweak from round 1. The blinding shares of the $w$ opening are committed to in round 2 and released in round 3 together with a discrete-log-equality proof, so that a participant sending an inconsistent $w_i$ is identified; the global check $W = g^{w}$ is removed. Key derivation is applied to the secret shares before round 1, and the last round is asymmetric with a coordinator collecting the signature shares.

### Note:  We denote $\mathcal{P}$ the set of participants included the DKG and the threshold $t = \mathsf{MaxMalicious}$

# Signing

In this phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}$
of size $N_1 = 2t +1$ wishes to generate an ECDSA signature.

The inputs to this phase are:
1) The secret key share $x_i$.
2) The public key $X$
3) A tweak $\epsilon$ used during key derivation
4) The message hash $h= H(m)$
5) The derived public key $Y = X + \epsilon \cdot G$

**Key Derivation:**

1. Each $P_i$ derives its signing share $x_i \gets x_i + \epsilon$

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
5. Each $P_i$ computes $B_i = g^{b_i}$ and $h_i \gets H(B_i)$
6. $\star$ Each $P_i$ sends $(R_i, w_i, h_i)$ to every party.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $(R_j, w_j, h_j)$ from each $P_j$.
2. $\blacktriangle$ Each $P_i$ *asserts* that:
$\forall j \in \\{t+2.. n\\},\quad \mathsf{ExponentInterpolation}(R_1, \ldots R_{t+1}; j) =  R_j$
3. Each $P_i$ computes $R \gets \mathsf{ExponentInterpolation}(R_1, \ldots R_{t+1}; 0)$
4. $\blacktriangle$ Each $P_i$ *asserts* that $R \neq Identity$
5. Each $P_i$ computes $w \gets \mathsf{Interpolation}(w_1, \ldots w_{2 \cdot t+1}; 0)$
6. $\blacktriangle$ Each $P_i$ *asserts* that $w \neq 0$.
7. Each $P_i$ computes $W_i \gets R^{a_i}$
8. Each $P_i$ computes $\pi_i \gets \mathsf{DLEQ.Prove}\big((R, W_i), (R_i, g^{w_i} \cdot B_i^{-1}); a_i\big)$
9. $\star$ Each $P_i$ sends $(W_i, B_i, \pi_i)$ to every party.

**Round 4:**

1. $\bullet$ Each $P_i$ waits to receive $(W_j, B_j, \pi_j)$ from every party.
2. $\blacktriangle$ Each $P_i$ *asserts* that:
$\forall j \in \\{t+2.. n\\},\quad \mathsf{ExponentInterpolation}(W_1, \ldots W_{t+1}; j) =  W_j$
3. $\blacktriangle$ For each $j$, each $P_i$ *asserts* that $H(B_j) = h_j$, identifying $P_j$ as malicious otherwise.
4. $\blacktriangle$ For each $j$, each $P_i$ *asserts* that $\mathsf{DLEQ.Verify}\big((R, W_j), (R_j, g^{w_j} \cdot B_j^{-1}); \pi_j\big)$ succeeds, identifying $P_j$ as malicious otherwise.
5. $\blacktriangle$ Each $P_i$ *asserts* that $\mathsf{ExponentInterpolation}(B_1, \ldots B_{2 \cdot t+1}; 0) = Identity$
6. Each $P_i$ computes $c_i \gets a_i \cdot w^{-1}$
7. Each $P_i$ computes $\alpha_i \gets c_i+d_i$
8. Each $P_i$ computes $\beta_i \gets c_i \cdot x_i$.
9. Each $P_i$ computes its signature share $s_i \gets \alpha_i * h + \beta_i \cdot R_\mathsf{x} + e_i$ where $R_\mathsf{x}$ is the x coordinate of $R$.
10. Each $P_i$ linearizes its signature share $s_i \gets \lambda_i(\mathcal{P}_1) s_i$.
11. $\star$ Each $P_i$ sends $s_i$ **only to the coordinator**.

**Round 4 (Coordinator):**

12. $\bullet$ The coordinator waits to receive $s_j$ from every party.
13. The coordinator sums the received elements $s \gets \sum_j s_j$.
14. $\blacktriangle$ The coordinator *asserts* that $s\neq 0$
15. Perform the low-S normalization, i.e. $s \gets -s$ if $s\in\\{\frac{q}{2}..~q-1\\}$
16. $\blacktriangle$ The coordinator asserts that $(R, s)$ is a valid ECDSA signature for $h$.

**Output:** the signature $(R, s)$.

*Note that such message-signature pair is only accepted by a verifier that uses a derived public key, i.e.,* $X + \epsilon\cdot G$.

**$\mathsf{DLEQ}$ proof** (Chaum-Pedersen, Fiat-Shamir) for bases $(G_0, G_1)$, publics $(Y_0, Y_1)$ and witness $a$ with $Y_0 = G_0^{a}$, $Y_1 = G_1^{a}$:

* $\mathsf{Prove}$: sample $\rho$; $K_0 \gets G_0^{\rho}$, $K_1 \gets G_1^{\rho}$; $e \gets H(\mathsf{sid}, G_0, Y_0, G_1, Y_1, K_0, K_1)$; $z \gets \rho + e \cdot a$; output $\pi = (e, z)$.
* $\mathsf{Verify}$: $K_0 \gets G_0^{z} \cdot Y_0^{-e}$, $K_1 \gets G_1^{z} \cdot Y_1^{-e}$; accept iff $e = H(\mathsf{sid}, G_0, Y_0, G_1, Y_1, K_0, K_1)$.

>  [click to see the Notation reference](../../network-layer.md#documentation-notation).

# Differences with [[DJNPO20](https://eprint.iacr.org/2020/501)]

Our specification introduces several modifications to the original paper, aimed at enhancing performance, security, and compatibility. The key changes are:

1. Sign computation optimization
2. Communication optimization
3. Identifiable check on the $w$ opening
4. Key derivation
5. Outsourcing the message hash

Changes (1) and (2) improve the overall performance of the scheme, change (3) strengthens the scheme's overall security, change (4) allows key derivation, and change (5) enhances compatibility with external systems that rely on this library for signing operations.

### Sign computation optimization
We require from the sender to linearize the value $s_i$ before sending it.
This amortizes the cost of computation for the receiver by $n-1$ lagrange coefficients computation and $n-1$ scalar multiplications.
The receiver only has to sum up the received values.

### Communication optimization
The original paper does not consider the existence of a coordinator and treats all the participants symmetrically.
Such choice can overload the network with $O(n^2)$ messages. Instead, we make the last round asymmetric and require
that each of the parties would only send their shares to the coordinator which combines them in the corresponding way.

### Identifiable check on the $w$ opening
Each participant commits to $B_i = g^{b_i}$ before the $w_j$ values are known and later proves that its $w_i$ is consistent with $W_i$ and $B_i$. A participant failing either check is identified.

### Key derivation
The key derivation is a feature that allows the holder of a secret key to derive multiple secret keys for different applications (e.g. an MPC node holding a secret key share that uses to derive several clients secret key shares).
The scheme remains correct after this key derivation.

### Outsourcing the message hash
Providing the signing protocol with raw hashes as inputs instead of the original messages is beneficial for many use cases, e.g., the signing nodes receive a hashed payload and are required to generate a signature that is valid for a "universal verifier". Note that such API is quite common in cryptographic libraries and has been intensively studied for the non-distributed case in [[PR24](https://link.springer.com/chapter/10.1007/978-3-031-57718-5_10)] and [[R25](https://www.research-collection.ethz.ch/bitstream/handle/20.500.11850/729349/uploaded-version.pdf?sequence=1)].

# Security considerations

Before implementing or using the robust ECDSA scheme implemented here,
be aware that it is vulnerable to **split-view attacks** in the robust setting when the
signing parameters are not globally consistent. If different subsets of size at least
$2t + 1$ sign different $(h, \epsilon)$ values using shares derived from the same
nonce, the resulting signatures use multiplicatively related nonces and the
secret key can be recovered using standard ECDSA nonce-reuse attacks.

Moreover, due to protocol modifications relative to [[DJNPO20](https://eprint.iacr.org/2020/501)] (notably signature-share
linearization), **a novel split-view attack exists that can extract the secret key using as
few as $2t + 2$ participants**, with as few as two signing sessions.

To reduce the risk of accidental misuse, enforce the following constraints:

1. **Use exactly $N_1 = 2t + 1$ participants.**
   Do **not** allow any deviation from this value.

   Allowing larger sets enables split-view attacks when a coordinator can run parallel or
   partially overlapping signing sessions.

2. **Ensure all participants agree on $(h, \epsilon)$ and the signing set.**
   The coordinator must not be able to present different message hashes, tweaks, or
   participant lists to different signers.

3. **Never reuse the nonce shares**, even across failed, aborted, or partially completed
   signing sessions.

4. **Do not sign with $h = 0$** (the zero message hash).
   This input enables a related algebraic split-view attack in the modified scheme when
   $N_1 > 2t + 1$.
