# Robust ECDSA — stub

> **Status: this is not a secure scheme.**
> The [[DJNPO20](https://eprint.iacr.org/2020/501)] implementation this document used
> to specify was removed. What remains is a stub that produces valid ECDSA
> signatures while leaking the signing key, kept so that the surrounding node and
> contract plumbing stays exercised until a real robust scheme replaces it.
> Never add a domain for this protocol on mainnet or testnet.
>
> The removed specification, including its security analysis of split-view attacks
> and its differences from the original paper, is available in this file's git
> history.

We keep the module's type surface, participant-count rules and threshold arithmetic
(`N = 2t + 1` signers for `t = MaxMalicious`) so that reintroducing a robust scheme
means rewriting one function rather than rebuilding the node's presignature storage,
task routing, resharing and contract-side threshold validation around it.

### Note: We denote $\mathcal{P}$ the set of participants included in the DKG and the threshold $t = \mathsf{MaxMalicious}$

# Presigning

A set of parties $\mathcal{P}_1 \subseteq \mathcal{P}$ of size exactly $N_1 = 2t + 1$
generates a presignature. The input to this phase is the secret key share $x_i$.

**Round 1:**

1. Each $P_i$ samples a random non-zero $k_i$.
2. $\star$ Each $P_i$ sends $k_i$ to every party.
3. $\bullet$ Each $P_i$ waits to receive $k_j$ from every other party.
4. Each $P_i$ computes the nonce $k \gets \sum_j k_j$ and $R \gets k \cdot G$.
5. $\blacktriangle$ Each $P_i$ *asserts* that $k \neq 0$.
6. Each $P_i$ sets $\alpha_i, c_i \gets k^{-1}$, $\beta_i \gets k^{-1} \cdot x_i$ and $e_i \gets 0$.

**Output:** the presignature $(R, \alpha_i, \beta_i, c_i, e_i)$.

$\alpha_i$ and $c_i$ are identical across parties rather than secret-shared. Because
Lagrange coefficients at zero sum to one, $\sum_i \lambda_i \alpha_i = k^{-1}$ holds
regardless, so the signing phase below recombines them correctly. $\beta_i$ is
scaled by the party's real key share, so $\sum_i \lambda_i \beta_i = k^{-1} x$.

**Why this leaks the key.** Every presigner learns $k$ in the clear, so given any
signature $(R, s)$ derived from this presignature the signing key follows from
$x = (s \cdot k - h) \cdot R_\mathsf{x}^{-1}$. The nonce $\delta$-rerandomization
below does not help: $\delta$ is derived from public inputs.

# Signing

Unchanged from the removed scheme, and scheme-agnostic: it sums Lagrange-linearized
shares of $s$ and provides no secrecy of its own.

A set of parties $\mathcal{P}_2 \subseteq \mathcal{P}_1$ of size $N_2 = 2t + 1$
generates an ECDSA signature. The inputs to this phase are:

1) The presignature $(R, \alpha_i, \beta_i, c_i, e_i)$,
2) The public key $X$,
3) A "fresh" public source of entropy $\rho$,
4) A tweak $\epsilon$ used during key derivation,
5) The message hash $h = H(m)$,
6) The derived public key $Y = X + \epsilon \cdot G$.

**Rerandomization & Key Derivation:**

1. Each $P_i$ derives a randomness $\delta \gets \mathsf{HKDF}(Y, \epsilon, h, R, \rho)$
2. Each $P_i$ rerandomizes the following elements:

    * $R  \gets R^\delta$
    * $\alpha_i \gets \alpha_i \cdot \delta^{-1}$
    * $\beta_i \gets (\beta_i + c_i \cdot \epsilon) \cdot \delta^{-1}$

**Round 1:**

1. Each $P_i$ computes its signature share $s_i \gets \alpha_i * h + \beta_i \cdot R_\mathsf{x} + e_i$ where $R_\mathsf{x}$ is the x coordinate of $R$.
2. Each $P_i$ linearizes its signature share $s_i \gets \lambda_i(\mathcal{P}_2) s_i$.
3. $\star$ Each $P_i$ sends $s_i$ **only to the coordinator**.

**Round 1 (Coordinator):**

3. $\bullet$ The coordinator waits to receive $s_j$ from every party.
4. The coordinator sums the received elements $s \gets \sum_j s_j$.
5. $\blacktriangle$ The coordinator *asserts* that $s\neq 0$
6. Perform the low-S normalization, i.e. $s \gets -s$ if $s\in\\{\frac{q}{2}..~q-1\\}$
7. $\blacktriangle$ The coordinator asserts that $(R, s)$ is a valid ECDSA signature for $h$.

**Output:** the signature $(R, s)$.

*Note that such message-signature pair is only accepted by a verifier that uses a derived public key, i.e.,* $X + \epsilon\cdot G$.

>  [click to see the Notation reference](../../network-layer.md#documentation-notation).
