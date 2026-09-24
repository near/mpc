This document specifies the signing protocol described in [[DJNPO20](https://eprint.iacr.org/2020/501)].

**We deviate from the original scheme in the following ways.** The protocol is a single four-round protocol whose inputs include the message hash and the tweak from round 1. The shares of $a$ and of the blinding value $b$ are dealt under Pedersen commitments in round 1, receivers verify their shares against them, and in round 3 every participant proves in zero knowledge that its $w_i$ opens consistently with its committed $a_i$ and $b_i$, so that a misbehaving dealer or participant is identified; the values $W_i = a_i \cdot R$ and the global check $W = w \cdot G$ are removed. Key derivation is applied to the secret shares before round 1, and the last round is asymmetric with a coordinator collecting the signature shares.

### Note:  We denote $\mathcal{P}$ the set of participants included the DKG and the threshold $t = \mathsf{MaxMalicious}$

# Signing

In this phase, a set of parties $\mathcal{P}_1 \subseteq \mathcal{P}$
of size $N_1 = 2t + 1$ wishes to generate an ECDSA signature.

The inputs to this phase are:
1) The secret key share $x_i$.
2) The public key $X$
3) A tweak $\epsilon$ used during key derivation
4) The message hash $h= H(m)$
5) The derived public key $Y = X + \epsilon \cdot G$

**Key Derivation:**

1. Each $P_i$ derives its signing share $x_i \gets x_i + \epsilon$

**Round 1:**

1. Each $P_i$ generates two random, degree $t$ polynomials $f_{k_i}$ and $f_{a_i}$
2. Each $P_i$ generates a random, degree $t$ polynomial $f_{\rho_i}$ with constant term zero.
3. Each $P_i$ generates three random, degree $2t$ polynomials $f_{b_i}$, $f_{d_i}$, and $f_{e_i}$ and set their constant terms to zero.
4. Each $P_i$ generates a random, degree $2t$ polynomial $f_{\sigma_i}$ with constant term zero
5. Each $P_i$ commits to $f_{a_i}$ and $f_{b_i}$:

$$
\hat f_{a_i} \gets \mathsf{Com}(f_{a_i}; f_{\rho_i}) \qquad
\hat f_{b_i} \gets \mathsf{Com}(f_{b_i}; f_{\sigma_i})
$$

   **Pedersen commitment:** $H_{\mathsf{ped}}$ denotes a second generator with unknown discrete logarithm, and $\mathsf{Com}(v; r) = v \cdot G + r \cdot H_{\mathsf{ped}}$.

   $\mathsf{Com}$ extends coefficientwise to polynomials: for $f(X) = \sum_m f_m X^m$ and $r(X) = \sum_m r_m X^m$, $\mathsf{Com}(f; r)$ is the polynomial with coefficients $\mathsf{Com}(f_m; r_m)$. Since $\mathsf{Com}$ is linear, $\mathsf{Com}(f; r)(j) = \mathsf{Com}(f(j); r(j))$.

$\quad$ *Note: the constant coefficient of* $\hat f_{b_i}$ *is the identity, since* $f_{b_i}$ *and* $f_{\sigma_i}$ *have constant term zero, and is not sent.*

6. $\star$ Each $P_i$ sends $(\hat f_{a_i}, \hat f_{b_i})$ to every party.
7. $\textcolor{red}{\star}$ Each $P_i$ **privately** sends
$(k_{ij}, a_{ij}, b_{ij}, d_{ij}, e_{ij}, \rho_{ij}, \sigma_{ij})$ to every party $P_j$ such that:

$$
k_{ij} \gets f_{k_i}(j) \qquad
a_{ij} \gets f_{a_i}(j) \qquad
b_{ij} \gets f_{b_i}(j) \qquad
d_{ij} \gets f_{d_i}(j) \qquad
e_{ij} \gets f_{e_i}(j) \qquad
\rho_{ij} \gets f_{\rho_i}(j) \qquad
\sigma_{ij} \gets f_{\sigma_i}(j)
$$

**Round 2:**

1. $\bullet$ Each $P_i$ waits to receive the committed polynomials $(\hat f_{a_j}, \hat f_{b_j})$ from each party $P_j$
2. $\bullet$ Each $P_i$ waits to receive $(k_{ji}, a_{ji}, b_{ji}, d_{ji}, e_{ji}, \rho_{ji}, \sigma_{ji})$ from each party $P_j$
3. $\blacktriangle$ Each $P_i$ *asserts* the following identifying whether $P_j$ is honest or malicious:

$$
\mathsf{Com}(a_{ji}; \rho_{ji}) = \hat f_{a_j}(i) \qquad
\mathsf{Com}(b_{ji}; \sigma_{ji}) = \hat f_{b_j}(i)
$$

4. Each $P_i$ sums the shares received from the participants:

$$
k_i \gets \sum_j k_{ji} \qquad
a_i \gets \sum_j a_{ji} \qquad
b_i \gets \sum_j b_{ji} \qquad
d_i \gets \sum_j d_{ji} \qquad
e_i \gets \sum_j e_{ji} \qquad
\rho_i \gets \sum_j \rho_{ji} \qquad
\sigma_i \gets \sum_j \sigma_{ji}
$$

5. Each $P_i$ sums the committed polynomials:

$$
\hat f_a \gets \sum_j \hat f_{a_j} \qquad \hat f_b \gets \sum_j \hat f_{b_j}
$$

$\quad$ *Note: it follows that* $\hat f_a(i) = \mathsf{Com}(a_i; \rho_i)$ *and* $\hat f_b(i) = \mathsf{Com}(b_i; \sigma_i)$*.*

6. Each $P_i$ computes $R_i \gets k_i \cdot G$
7. Each $P_i$ computes $w_i \gets a_i \cdot k_i + b_i \quad$ ($b_i$ being a blinding factor for $a_i \cdot k_i$)
8. Each $P_i$ computes the hash $\eta_i \gets H\big(\{(\hat f_{a_j}, \hat f_{b_j})\}_{j \in \mathcal{P}_1}\big)$
9. $\star$ Each $P_i$ sends $(R_i, w_i, \eta_i)$ to every party.

**Round 3:**

1. $\bullet$ Each $P_i$ waits to receive $(R_j, w_j, \eta_j)$ from each $P_j$, and $\blacktriangle$ *asserts* that $\eta_j = \eta_i$.
2. $\blacktriangle$ Each $P_i$ *asserts* that:
$\forall j \in \set{t+2.. N_1},\quad \mathsf{Interpolation}(R_1, \ldots R_{t+1}; j) =  R_j$
3. Each $P_i$ computes $R \gets \mathsf{Interpolation}(R_1, \ldots R_{t+1}; 0)$
4. $\blacktriangle$ Each $P_i$ *asserts* that $R \neq Identity$
5. Each $P_i$ computes $w \gets \mathsf{Interpolation}(w_1, \ldots w_{2 \cdot t+1}; 0)$
6. $\blacktriangle$ Each $P_i$ *asserts* that $w \neq 0$.
7. Each $P_i$ computes $\pi_i \gets \mathsf{Prove}\big(w_i \cdot G, \hat f_a(i), \hat f_b(i), R_i;\ a_i, b_i, \rho_i, \sigma_i\big)$

   **Proof of the $w_i$ opening** (sigma protocol, Fiat-Shamir) for the statement, with witness $(a_i, b_i, \rho_i, \sigma_i)$:

   $$
   w_i \cdot G = a_i \cdot R_i + b_i \cdot G \qquad
   \hat f_a(i) = a_i \cdot G + \rho_i \cdot H_{\mathsf{ped}} \qquad
   \hat f_b(i) = b_i \cdot G + \sigma_i \cdot H_{\mathsf{ped}}
   $$

   * $\mathsf{Prove}$:
      * sample $(u_a, u_b, u_\rho, u_\sigma)$
      * compute $K_0 \gets u_a \cdot R_i + u_b \cdot G$, $K_1 \gets u_a \cdot G + u_\rho \cdot H_{\mathsf{ped}}$, $K_2 \gets u_b \cdot G + u_\sigma \cdot H_{\mathsf{ped}}$
      * compute $e \gets H(\mathsf{sid}, i, w_i \cdot G, \hat f_a(i), \hat f_b(i), R_i, K_0, K_1, K_2)$
      * compute $z_a \gets u_a + e a_i$, $z_b \gets u_b + e b_i$, $z_\rho \gets u_\rho + e \rho_i$, $z_\sigma \gets u_\sigma + e \sigma_i$
      * output $\pi_i = (e, z_a, z_b, z_\rho, z_\sigma)$

8. $\star$ Each $P_i$ sends $\pi_i$ to every party.

**Round 4:**

1. $\bullet$ Each $P_i$ waits to receive $\pi_j$ from every party.
2. $\blacktriangle$ For each $j$, each $P_i$ *asserts* that $\mathsf{Verify}\big(w_j \cdot G, \hat f_a(j), \hat f_b(j), R_j;\ \pi_j\big)$ succeeds, identifying $P_j$ as malicious otherwise.
   * $\mathsf{Verify}$, parsing $\pi_j = (e, z_a, z_b, z_\rho, z_\sigma)$:
      * compute $K_0 \gets z_a \cdot R_j + z_b \cdot G - e \cdot (w_j \cdot G)$
      * compute $K_1 \gets z_a \cdot G + z_\rho \cdot H_{\mathsf{ped}} - e \cdot \hat f_a(j)$
      * compute $K_2 \gets z_b \cdot G + z_\sigma \cdot H_{\mathsf{ped}} - e \cdot \hat f_b(j)$
      * accept iff $e = H(\mathsf{sid}, j, w_j \cdot G, \hat f_a(j), \hat f_b(j), R_j, K_0, K_1, K_2)$


3. Each $P_i$ computes $c_i \gets a_i \cdot w^{-1}$
4. Each $P_i$ computes $\alpha_i \gets c_i+d_i$
5. Each $P_i$ computes $\beta_i \gets c_i \cdot x_i$.
6. Each $P_i$ computes its signature share $s_i \gets \alpha_i \cdot h + \beta_i \cdot R_\mathsf{x} + e_i$ where $R_\mathsf{x}$ is the x coordinate of $R$.
7. Each $P_i$ linearizes its signature share $s_i \gets \lambda_i(\mathcal{P}_1) s_i$.
8. $\star$ Each $P_i$ sends $s_i$ **only to the coordinator**.

**Round 4 (Coordinator):**

9. $\bullet$ The coordinator waits to receive $s_j$ from every party.
10. The coordinator sums the received elements $s \gets \sum_j s_j$.
11. $\blacktriangle$ The coordinator *asserts* that $s\neq 0$
12. Perform the low-S normalization, i.e. $s \gets -s$ if $s\in\set{\frac{q}{2}..~q-1}$
13. $\blacktriangle$ The coordinator asserts that $(R, s)$ is a valid ECDSA signature for $h$.

**Output:** the signature $(R, s)$.

*Note that such message-signature pair is only accepted by a verifier that uses a derived public key, i.e.,* $X + \epsilon\cdot G$.


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
The shares of $a$ and $b$ are dealt under Pedersen commitments, and each participant proves that its $w_i$ is consistent with its committed $a_i$ and $b_i$. A dealer or participant failing a check is identified.

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
