# Distributed Key Generation

We define a variant of the two-round Distributed Key Generation (DKG) protocol PedPop \[[KG](https://eprint.iacr.org/2020/852.pdf)\].
Our variant, PedPop+ is less efficient, but achieves a notion of simulatability with aborts,
a stronger notion of security than the one promised by plain PedPop.

PedPop+ is a five-and-a-half-rounds protocol and makes use in three of its rounds of a reliable broadcast channel. A reliable broadcast is a three-round protocol,
implying that the effective total number of PedPop+ rounds is eleven and a half. The broadcast channel is implemented in `src/protocol/echo_broadcast.rs`.

The implemented DKG serves as a generic one that can be used with multiple different underlying elliptic curves. We thus use it with `Secp256k1` for ECDSA schemes, `Curve25519` for EdDSA scheme, and `BLS12-381` for the confidential key derivation functionality.

## Keygen, Reshare and Refresh

The core of the DKG protocol is implemented in a function called `do_keyshare` and serves for three applications:

* Key generation: denoted in the implementation with `keygen`. It allows a set of parties to jointly generate from scratch a private key share each and a master public key. The master public key should be common for all the participants and should reflect each of the private shares.

* Key resharing: denoted in the implementation with `reshare`. It allows for a set of participants who already own valid private shares to kick out other participants from the pool, create fresh shares for new participants i.e. new joiners to the pool, and/or change the **cryptographic threshold** described in section [Types of Thresholds](#types-of-thresholds).

* Key refresh: denoted in the implementation with `refresh`. It is a special case of the key resharing in which the set of participants stays the same before and after the protocol run and with no changes to the crypto. The goal being that each participant would refresh their signing share without modifying the master public key.

## Types of Thresholds

There are two types of thresholds one has to be aware of: the **asynchronous distributed systems threshold** a.k.a. the **BFT threshold** ($\mathsf{MaxFaulty}$), and the **cryptography threshold** a.k.a. the **reconstruction threshold** ($\mathsf{threshold}$). A detailed discussion of these thresholds can be found in the [Appendix](#appendix-on-the-discussion-of-threshold-types) section.

### DKG and thresholds

Due to the fact that PedPop+ utilizes reliable broadcast channel to securely generate private shares, it thus lies on the edge between the asynchronous distributed systems and cryptography. For this reason, we set
$\mathsf{MaxFaulty} = \frac{N - 1}{3}$ as an invariable parameter and allow our key generation and key resharing protocols to fix/modify only the $\mathsf{threshold}$ depending on the scheme requirements and on the library user's choice.

## Technical Details: Key Generation & Key Resharing

Let $P_1, \cdots P_N$ be $N$ different participants, and $\mathsf{threshold}$ be the desired cryptography threshold. Let $H_1, H_2, H_3$ be domain separated hash functions.

We define PedPop+ key generation as follows, where all the instructions preceded with `+++` are added to the key generation, transforming it to the key resharing protocol.

No special inputs are given to the **key generation** protocol beyond the public parameters defined above. However, the inputs to the **key resharing** are as follows:

1. `+++` The old private share $\mathit{secret}_i$ that $P_i$ held prior to the key resharing. This value is set to None only if $P_i$ is a freshly new participant.

2. `+++` The old participants set $\mathit{OldSigners}$ that held valid private shares prior to the key resharing.

3. `+++` The old master public key $\mathit{OldPK}$ that the $\mathit{OldSigners}$ held prior to the key resharing.

4. `+++` The old cryptography threshold $\mathsf{OldThreshold}$ prior to the key resharing.
``

### Round 1

1.1 Each $P_i$ asserts that $1 < \mathsf{threshold} < N$.

$\quad$ `+++` Each $P_i$ sets $I \gets \set{P_1 \ldots P_N} \cap \mathit{OldSigners}$

$\quad$ `+++` Each $P_i$ asserts that $\mathsf{OldThreshold} \leq |I|$.

1.2 Each $P_i$ generates a random 32-byte sesssion identifier $\mathit{sid}_i$

1.3 Each $P_i$ reliably broadcasts $\mathit{sid}_i$

### Round 2

2.1 Each $P_i$ waits to receive $\mathit{sid}_j$ from every participant $P_j$

2.2 Each $P_i$ computes the hash $\mathit{sid} \gets H_1(\mathit{sid}_1, \cdots \mathit{sid}_N)$

2.3 Each $P_i$ generates a random polynomial $f_i$ of degree $\mathsf{threshold}-1$.


$\quad$ `+++` Each $P_i$ computes the following:

$\quad$ `+++` If $P_i\notin \mathit{OldSigners}$ then set $f_i(0) \gets 0$

$\quad$ `+++` Else set $f_i(0) \gets \lambda_i(I) \cdot \mathit{secret}_i$
where $\lambda_i(I)$ is the lagrange coefficient defined as:

$$\lambda_i(I) = \prod_{j\in I\setminus \set{i}} \frac{j}{i-j}$$


2.4 Each $P_i$ generates a commitment of the polynomial $C_i \gets f_i \cdot G$ (commits every coefficient of the polynomial).

2.5 Each $P_i$ picks a random nonce $k_i$ and computes $R_i \gets k_i \cdot G$

2.6 Each $P_i$ computes the Schnorr challenge $c_i \gets H_3(\mathit{sid}, i, C_i(0), R_i)$

2.7 Each $P_i$ computes the proof $s_i \gets k_i + f_i(0) \cdot c_i$

2.8 Each $P_i$ generates a hash $h_i \gets H_2(i, C_i, \mathit{sid})$

2.9 Each $P_i$ sends $h_i$ to every participant

### Round 3

3.1 Each $P_i$ waits to receive $h_j$ from every participant $P_j$.

3.2 Each $P_i$ reliably broadcasts $(C_i, R_i, s_i)$.

### Round 4

4.1 Each $P_i$ waits to receive $(C_j, R_j, s_j)$ from every participant $P_j$.

4.2 Each $P_i$ computes: $\forall j\in\set{1, \cdots N}, \quad c_j \gets H_3(\mathit{sid}, j, C_j(0), R_j)$.

4.3 Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad R_j = s_j \cdot G - c_j \cdot C_j(0)$.

4.4 Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad h_j = H_2(j, C_j, \mathit{sid})$.

4.5 Each $P_i$ computes the master public key $\mathit{pk} \gets \sum_j C_j(0)$.

$\quad$ `+++` Each $P_i$ asserts that $\mathit{pk} = \mathit{OldPK}$

4.6 $\textcolor{red}{\star}$ Each $P_i$ **privately** sends the evaluation $f_i(j)$ to every participant $P_j$.

### Round 5

5.1 Each $P_i$ waits to receive $f_j(i)$ from every participant $P_j$.

5.2 Each $P_i$ asserts that: $\forall j\in\set{1, \cdots N}, \quad f_j(i) \cdot G = \sum_m j^m \cdot C_j[m]$ where $C_j[m]$ denotes the m-th coefficient of $C_j$.

5.3 Each $P_i$ computes its private share $\mathit{sk}_i \gets \sum_j f_j(i)$.

5.4 Each $P_i$ reliably broadcasts $\mathsf{success_i}$.

#### Round 5.5

5.5 Each $P_i$ waits to receive $\mathsf{success_j}$ from every participant $P_j$.

**Output:** the keypair $(\mathit{sk}_i, \mathit{pk})$.


### Key Refresh

A key refresh protocol is a special case of the key resharing where $\mathit{OldSigners} = \set{P_1, \ldots P_N}$ and where $\mathsf{OldThreshold} = \mathsf{threshold}$


## Appendix: On the Discussion of Threshold Types

The BFT threshold states that the maximum number of faulty nodes a distributed system ($\mathsf{MaxFaulty}$) can tolerate while still reaching consensus has the following bound $\mathsf{MaxFaulty} = \frac{N - 1}{3}$ where $N$ is the total number of nodes.

The cryptographic threshold refers to the maximum number of malicious parties plus one ($\mathsf{threshold}$) that a scheme can tolerate without compromising security, assuming the existence of an underlying reliable broadcast channel. $\mathsf{threshold}$ is scheme dependent and can have a different value than $\mathsf{MaxFaulty}$. For instance, in the OT based ECDSA, $\mathsf{threshold}$ can be up to $N$, but in Robust ECDSA scheme $\mathsf{threshold}$ must not exceed $\frac{N - 1}{2}+1$.

Here could be asked an interesting question:
If the maximum number of faulty participants is 1/3 for the broadcast protocol, how is it possible that we use much higher cryptographic threshold during DKG (say for signing with 6 participants out of 9). Shouldn't we be constrained to fix the cryptographic threshold to 1/3 too?

The answer goes in both directions:

* No, we should not be constrained to fix the cryptographic threshold to 1/3: one can assume having more "honest" nodes during key generation (which is ran supposedly once) than during the cryptographic signing phase (which should always happen). One can think of this extra parties being corrupt right after the key generation.

* Yes, we should fix the cryptographic threshold to 1/3. In fact it does not make sense to assume two different thresholds...

The separation between these two thresholds seldom appears in cryptographic academic papers, which, as mentioned above, often assume underlying broadcast channels. The motivation for explicitly introducing this separation is to enable library users to properly understand the implications of using this implementation, thereby avoiding potentially disastrous misconfigurations.